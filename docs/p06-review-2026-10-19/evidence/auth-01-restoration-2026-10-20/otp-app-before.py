import hashlib
import hmac
import os
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

import psycopg
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row

DB_URL = os.environ["OTP_DATABASE_URL"]
SCHEMA = os.environ.get("OTP_DATABASE_SCHEMA", "p3_auth")
INTERNAL_TOKEN = os.environ["OTP_INTERNAL_TOKEN"]
SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.environ["SMTP_PORT"])
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
SMTP_FROM = os.environ["SMTP_FROM"]
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "true").lower() == "true"
SMTP_SSL = os.environ.get("SMTP_SSL", "false").lower() == "true"
CODE_TTL = int(os.environ.get("OTP_CODE_TTL_SECONDS", "600"))

if not SCHEMA.replace("_", "").isalnum():
    raise RuntimeError("invalid database schema")

APP = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def db():
    return psycopg.connect(DB_URL, row_factory=dict_row)


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def authorized(token: str) -> bool:
    return bool(token) and hmac.compare_digest(token, INTERNAL_TOKEN)


def error(status: int, name: str):
    return JSONResponse(status_code=status, content={"ok": False, "error": name})


def send_email(email: str, code: str):
    message = EmailMessage()
    message["Subject"] = "LiveUIN verification code"
    message["From"] = SMTP_FROM
    message["To"] = email
    message.set_content(
        "Your LiveUIN verification code is "
        f"{code}. It expires in {CODE_TTL // 60} minutes."
    )

    if SMTP_SSL:
        client = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)
    else:
        client = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)

    with client:
        if SMTP_STARTTLS and not SMTP_SSL:
            client.starttls()
        if SMTP_USER:
            client.login(SMTP_USER, SMTP_PASS)
        client.send_message(message)


def internal_header(
    x_otp_internal_token: str = Header(
        default="",
        alias="X-OTP-Internal-Token",
    ),
) -> str:
    return x_otp_internal_token


@APP.get("/healthz")
def healthz():
    return {"ok": True, "ready": True, "service": "liveuin-otp-smtp-pg"}


@APP.get("/readyz")
def readyz():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return {"ok": True, "ready": True, "service": "liveuin-otp-smtp-pg"}
    except Exception:
        return error(503, "not_ready")


@APP.post("/send")
def send_code(payload: dict, token: str = internal_header()):
    if not authorized(token):
        return error(401, "internal_authentication_required")

    email = str(payload.get("email", "")).strip().lower()
    challenge_id = str(payload.get("challenge_id", "")).strip()

    if not email or not challenge_id:
        return error(400, "email_and_challenge_id_required")

    supplied_code = str(payload.get("verification_code", "")).strip()
    if supplied_code and (len(supplied_code) != 6 or not supplied_code.isdigit()):
        return error(400, "invalid_verification_code")
    # Core owns the challenge and verification code; the gateway owns SMTP delivery only.
    code = supplied_code or f"{secrets.randbelow(1_000_000):06d}"
    delivery_id = secrets.token_urlsafe(18)
    expires = datetime.now(timezone.utc) + timedelta(seconds=CODE_TTL)

    try:
        with db() as conn:
            conn.execute(
                f"""
                INSERT INTO {SCHEMA}.otp_deliveries
                    (delivery_id, challenge_id, email, code_hash, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    delivery_id,
                    challenge_id,
                    email,
                    code_hash(code),
                    expires,
                ),
            )
            send_email(email, code)
    except (OSError, smtplib.SMTPException):
        return error(502, "smtp_delivery_failed")
    except Exception:
        return error(502, "otp_storage_or_delivery_failed")

    return {"ok": True, "sent": True}


@APP.post("/verify")
def verify_code(payload: dict, token: str = internal_header()):
    if not authorized(token):
        return error(401, "internal_authentication_required")

    email = str(payload.get("email", "")).strip().lower()
    challenge_id = str(payload.get("challenge_id", "")).strip()
    code = str(payload.get("code", "")).strip()

    if not email or not challenge_id or not code:
        return error(400, "verification_fields_required")

    with db() as conn:
        delivery = conn.execute(
            f"""
            SELECT delivery_id, code_hash
            FROM {SCHEMA}.otp_deliveries
            WHERE challenge_id = %s
              AND lower(email) = lower(%s)
              AND verified_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (challenge_id, email),
        ).fetchone()

        if not delivery:
            return error(401, "invalid_or_expired_code")

        if not hmac.compare_digest(
            delivery["code_hash"],
            code_hash(code),
        ):
            return error(401, "invalid_or_expired_code")

        conn.execute(
            f"""
            UPDATE {SCHEMA}.otp_deliveries
            SET verified_at = CURRENT_TIMESTAMP
            WHERE delivery_id = %s
            """,
            (delivery["delivery_id"],),
        )

    return {"ok": True, "valid": True}


app = APP
