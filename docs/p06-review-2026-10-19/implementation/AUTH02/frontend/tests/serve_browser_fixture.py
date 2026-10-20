"""ISOLATED LOCAL FIXTURE. Never deploy; no upstream request or real account.

Copies the pinned candidate graph, substitutes the App-origin predicate for
loopback HTTP and pins the legacy host classifier to App (not local preview),
then serves synthetic Identity responses in memory.
All unrecognised API routes are denied. CSP blocks external connections.
"""
import hashlib
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import mimetypes
from pathlib import Path
import shutil
import time
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = json.loads((ROOT / "candidate-manifest.json").read_text())
FIXTURE = ROOT / "browser-fixture"
EMAIL = "test.parent@auth02.invalid"
PASSWORD = "Auth02-fixture-only!"
if FIXTURE.exists():
    shutil.rmtree(FIXTURE)
shutil.copytree(ROOT / "candidate", FIXTURE)
index = FIXTURE / "assets" / MANIFEST["release_id"] / "index-DPZwxwE9.js"
old = b'window.location.protocol === "https:" &&\n    window.location.hostname === "app.liveuin.com"'
new = b'window.location.protocol === "http:" &&\n    window.location.hostname === "127.0.0.1"'
data = index.read_bytes()
assert data.count(old) == 1
host_old = b'ke=()=>{const e=px();if(typeof window>"u"||!Pc(e))return e;const t=new URLSearchParams(window.location.search||""),n=String(t.get("preview_host")||t.get("previewHost")||"").toLowerCase().trim();return n||e}'
host_new = b'ke=()=>"app.liveuin.com"'
assert data.count(host_old) == 1
index.write_bytes(data.replace(old, new).replace(host_old, host_new))
fixture_note = {
    "deployable": False, "purpose": "Local synthetic React/router/browser smoke only",
    "candidate_manifest_sha256": hashlib.sha256((ROOT / "candidate-manifest.json").read_bytes()).hexdigest(),
    "candidate_index_sha256": hashlib.sha256(data).hexdigest(),
    "fixture_index_sha256": hashlib.sha256(index.read_bytes()).hexdigest(),
    "javascript_deltas": ["auth02IsApp accepts HTTP 127.0.0.1 instead of HTTPS app.liveuin.com",
                          "legacy host classifier reports App in the loopback fixture; avoids local preview fallback"],
    "real_accounts_or_network_proxy": False,
}
(FIXTURE / "NOT-DEPLOYABLE.json").write_text(json.dumps(fixture_note, indent=2) + "\n")
sessions = {}
events = []
counter = 0

def projection():
    row = {"entitlement_id": "ent_fixture_parent", "account_id": "account_fixture_parent",
           "person_id": "person_fixture_parent", "workspace_id": "wsp_fixture_test",
           "profile_key": "tenant", "status": "active", "effective_to": 0,
           "effective_from": 0, "expires_at": "", "is_default": True,
           "subject_id": "person_fixture_parent", "subject_role": "tenant",
           "allowed_actions": ["tenant"], "permissions": ["tenant"],
           "route_restrictions": [], "default_route": "/tenant/home"}
    return {"ok": True, "status": "identity_session_resolved", "account_id": row["account_id"],
            "person_id": row["person_id"], "workspace_id": row["workspace_id"],
            "actor": {"account_id": row["account_id"], "person_id": row["person_id"],
                      "actor_id": row["person_id"], "role": "tenant", "display_name": "AUTH02 Fixture Parent",
                      "active_profile_key": "tenant", "active_workspace_id": row["workspace_id"], "scopes": ["tenant"]},
            "identity_session": {"resolved": True, "verified": True,
                                 "credential_kind": "liveuin_session", "public_identity_session": True},
            "authorized_profiles": [row.copy()], "profile_entitlements": [row.copy()],
            "profile_state": "tenant_active", "next_action": "tenant_home", "access": {"case_ids": []}}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, status, body, content_type="application/json"):
        data = json.dumps(body).encode() if content_type == "application/json" else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'none'; base-uri 'self'; form-action 'self'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def session(self):
        identity = self.headers.get("X-LiveUIN-Session-Id", "")
        record = sessions.get(identity)
        if not record or record["revoked"] or record["expires_at"] <= time.time():
            return None
        for key, value in record["headers"].items():
            if self.headers.get(key) != value:
                return None
        return record

    def do_POST(self):
        global counter
        route = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        if length > 10000:
            return self.send(413, {"ok": False, "error": {"code": "fixture_body_limit"}})
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return self.send(400, {"ok": False})
        if route == "/api/core/identity/sessions/password":
            if payload != {"email": EMAIL, "password": PASSWORD}:
                events.append({"action": "password", "status": 401})
                return self.send(401, {"ok": False, "error": {"code": "invalid_credentials", "message": "Invalid fixture credentials"}})
            counter += 1
            sid = f"session_fixture_{counter}"
            headers = {"X-LiveUIN-Workspace-Id": "wsp_fixture_test", "X-LiveUIN-Actor-Id": "person_fixture_parent",
                       "X-LiveUIN-Role": "member", "X-LiveUIN-Scopes": "identity.session,tenant",
                       "X-LiveUIN-Session-Id": sid, "X-LiveUIN-Session-Issued-At": str(int(time.time())),
                       "X-LiveUIN-Auth-Method": "public_password", "X-LiveUIN-Session-Signature": "fixture_signature_" + str(counter)}
            record = {"headers": headers, "expires_at": int(time.time()) + 3600, "revoked": False}
            sessions[sid] = record
            events.append({"action": "password", "status": 200})
            return self.send(200, {"ok": True, "status": "authenticated", "profile_state": "tenant_active",
                                  "next_action": "tenant_home", "authorized_profiles": projection()["authorized_profiles"],
                                  "one_time_credential": {"credential_kind": "liveuin_session", "session_id": sid,
                                                          "session_headers": headers, "expires_at": record["expires_at"]},
                                  "refresh_token": "fixture_unused_refresh"})
        if route == "/api/core/identity/session/resolve":
            permitted = self.session() is not None
            events.append({"action": "resolve", "status": 200 if permitted else 401})
            return self.send(200, projection()) if permitted else self.send(401, {"ok": False, "error": {"code": "identity_session_required"}})
        if route == "/api/core/identity/logout":
            record = self.session()
            if not record:
                events.append({"action": "logout", "status": 401})
                return self.send(401, {"ok": False, "error": {"code": "identity_session_required"}})
            record["revoked"] = True
            events.append({"action": "logout", "status": 200})
            return self.send(200, {"ok": True, "status": "identity_session_logged_out", "public_refresh_credentials_revoked": 1})
        events.append({"action": "denied_unrecognised_api", "route": route, "status": 403})
        return self.send(403, {"ok": False, "error": {"code": "fixture_route_not_authorised"}})

    def do_GET(self):
        route = unquote(urlsplit(self.path).path)
        if route == "/__fixture/status":
            return self.send(200, {"fixture": True, "deployable": False,
                                   "active_sessions": sum(not s["revoked"] for s in sessions.values()),
                                   "revoked_sessions": sum(s["revoked"] for s in sessions.values()),
                                   "events": events[-80:]})
        if route.startswith("/api/"):
            events.append({"action": "denied_unrecognised_api", "route": route, "status": 403})
            return self.send(403, {"ok": False, "error": {"code": "fixture_route_not_authorised"}})
        if ".." in Path(route).parts or "\\" in route:
            return self.send(403, {"ok": False})
        target = (FIXTURE / route.lstrip("/")).resolve()
        if not target.is_relative_to(FIXTURE):
            return self.send(403, {"ok": False})
        if not target.is_file() and route.startswith("/assets/"):
            target = (ROOT / "baseline" / route.lstrip("/")).resolve()
        if target.is_file():
            return self.send(200, target.read_bytes(), mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        if route.startswith("/assets/") or Path(route).suffix:
            return self.send(404, {"ok": False})
        html = (FIXTURE / "app-entry.html").read_bytes()
        marker = b'<div style="position:fixed;bottom:0;left:0;right:0;z-index:99999;background:#fef3c7;color:#000;padding:4px;font:12px sans-serif;text-align:center">LOCAL AUTH02 FIXTURE ONLY - synthetic account, no LiveUIN production access</div>'
        html = html.replace(b"</body>", marker + b"</body>")
        return self.send(200, html, "text/html; charset=utf-8")

    do_HEAD = do_GET

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
details = {**fixture_note, "url": f"http://127.0.0.1:{port}/auth/sign-in?returnTo=%2Ftenant%2Fhome",
           "status_url": f"http://127.0.0.1:{port}/__fixture/status", "email": EMAIL, "password": PASSWORD}
(ROOT / "browser-fixture-session.json").write_text(json.dumps(details, indent=2) + "\n")
print(json.dumps(details), flush=True)
server.serve_forever()
