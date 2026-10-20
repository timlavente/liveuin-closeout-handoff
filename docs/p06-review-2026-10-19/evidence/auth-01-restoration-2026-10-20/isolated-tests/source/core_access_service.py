from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from typing import Any, Dict, List, Set

try:
    from . import core_access_store as store
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_access_store as store

try:
    from . import core_adapter_replay_store as replay_store
except ImportError:  # pragma: no cover - supports direct script execution.
    try:
        import core_adapter_replay_store as replay_store
    except ImportError:  # pragma: no cover - supports partial deploys.
        replay_store = None  # type: ignore

try:
    from . import core_adapter_secret_registry as secret_registry
except ImportError:  # pragma: no cover - supports direct script execution.
    try:
        import core_adapter_secret_registry as secret_registry
    except ImportError:  # pragma: no cover - registry is optional during partial deploys.
        secret_registry = None  # type: ignore


SCHEMA_VERSION = "liveuin-core-access-governance-v1"
PHASE = "phase29-shared-adapter-replay-store-contract"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Core/Admin Access Governance"
ACTIVE_PARTICIPANT_GRANT_STATUSES = {"active", "limited"}
PARTICIPANT_GRANT_STATUSES = {
    "proposed",
    "invited",
    "pending_evidence",
    "active",
    "limited",
    "expired",
    "withdrawn",
    "suspended",
    "disputed",
    "superseded",
    "revoked",
    "draft_not_effective",
}
DENIED_PARTICIPANT_GRANT_STATUSES = PARTICIPANT_GRANT_STATUSES - ACTIVE_PARTICIPANT_GRANT_STATUSES
CONSENT_ACTIVE_STATES = {"consented", "guardian_consented", "operator_approved", "approved"}
CONSENT_DENIED_STATES = {"declined", "withdrawn", "expired", "superseded", "disputed", "revoked", "not_consented", "missing"}
AUTHORITY_ACTIVE_STATES = {"verified", "guardian_verified", "self_authorized", "operator_verified", "delegated_verified"}
AUTHORITY_DENIED_STATES = {"missing", "unknown", "pending", "pending_evidence", "disputed", "expired", "withdrawn", "revoked", "superseded", "declined"}
DISCLOSURE_MODELS = {
    "least_privilege_public_pass_projection",
    "least_privilege_participant_projection",
    "participant_private_projection",
    "protected_media_delivery",
    "audit_restricted",
}

SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "bank_account",
    "card_number",
    "checkout_url",
    "client_secret",
    "document_uri",
    "identity_document",
    "password",
    "private_note",
    "private_url",
    "provider_payload",
    "raw_body",
    "raw_payload",
    "secret",
    "signature",
    "signed_url",
    "storage_uri",
    "token",
}

CLAIM_OWNERS = {
    "case": "LiveUIN Core",
    "case_status": "LiveUIN Core",
    "inventory": "LiveUIN Inventory",
    "hold": "LiveUIN Inventory / Booking",
    "room_passport": "LiveUIN Trust",
    "proof": "LiveUIN Trust",
    "media": "LiveUIN Media/Auth",
    "viewing": "LiveUIN Viewing/Scheduler",
    "booking": "LiveUIN Booking/TrustPay",
    "deposit": "LiveUIN Booking/TrustPay",
    "payment": "LiveUIN TrustPay/LiveLedger",
    "payment_status": "LiveUIN TrustPay/LiveLedger",
    "settlement": "LiveUIN TrustPay/LiveLedger",
    "ledger": "LiveUIN TrustPay/LiveLedger",
    "ledger_export": "LiveUIN TrustPay/LiveLedger",
    "verification": "LiveUIN Trust / Identity",
    "ticket": "LiveUIN Ops",
    "task": "LiveUIN Ops",
    "resolution": "LiveUIN Ops / Resolution OS",
    "move_in": "LiveUIN Booking / Trust / Ops",
    "lifecycle": "LiveUIN Ops / Lifecycle",
    "improvement": "LiveUIN Analytics / Ops / Resolution OS",
    "remediation": "LiveUIN Ops / Vendor Ops / Property Finance",
    "analytics": "LiveUIN Analytics",
    "demand": "LiveUIN Demand OS",
    "intelligence": "LiveUIN Intelligence",
    "owner_contact": "LiveUIN Owner Ops Runtime",
    "contract_template": "LiveUIN ContractOps Runtime",
    "contract_draft": "LiveUIN Contract Builder Runtime",
    "support_profile": "LiveUIN Support Runtime",
    "service_claim": "LiveUIN service-policy/claims registry",
    "living_saved_search": "LiveUIN Living Runtime",
    "living_application": "LiveUIN Application Locker Runtime",
    "partner": "LiveUIN Partner/Core",
    "marketplace": "LiveUIN Marketplace Layer",
    "compliance": "LiveUIN Compliance",
    "connector_setup": "LiveUIN Connect",
}

CANONICAL_SOURCE_FAMILIES = {
    "liveuin_core",
    "liveuin_identity",
    "liveuin_inventory",
    "liveuin_trust",
    "liveuin_media_auth",
    "liveuin_viewing",
    "liveuin_booking",
    "liveuin_trustpay",
    "liveuin_liveledger",
    "liveuin_verification",
    "liveuin_ops",
    "liveuin_resolution",
    "liveuin_movein",
    "liveuin_lifecycle",
    "liveuin_improvement",
    "liveuin_remediation",
    "liveuin_analytics",
    "liveuin_demand",
    "liveuin_intelligence",
    "liveuin_owner_ops",
    "liveuin_contract_ops",
    "liveuin_support",
    "liveuin_living",
    "liveuin_marketplace",
    "liveuin_compliance_publish_gates",
    "liveuin_compliance_marketplace_integrity",
    "liveuin_partner_core",
    "liveuin_partner_marketplace",
    "liveuin_vendor_runtime",
}

ADAPTER_EVIDENCE_FAMILIES = {
    "payment_provider",
    "psp_webhook",
    "bank_feed",
    "kyc_provider",
    "e_sign_provider",
    "object_storage",
    "channel_callback",
    "wordpress_connector",
}

DISPLAY_OR_BRIDGE_FAMILIES = {
    "bank_portal",
    "psp_dashboard",
    "wechat",
    "wechat_pay",
    "wordpress_connector",
    "liveuin_connector",
    "laijuzhu_ui",
    "igema_notes",
    "operator_chat",
    "vendor_spreadsheet",
    "report_export",
    "ui_export",
    "ai_prompt_cache",
    "file_folder",
}

POLICIES: Dict[str, Dict[str, Any]] = {
    "ledger.batch.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_ops", "finance_manager", "super_admin"},
        "scopes": {"finance.settlement.prepare"},
        "claim_type": "settlement",
        "canonical_source_required": True,
    },
    "ledger.account.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_manager", "super_admin"},
        "scopes": {"finance.ledger.account.write"},
        "claim_type": "ledger",
        "canonical_source_required": True,
    },
    "ledger.batch.post": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_manager", "super_admin"},
        "scopes": {"finance.ledger.post"},
        "claim_type": "ledger",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "ledger.export.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"accountant", "finance_manager", "super_admin"},
        "scopes": {"finance.export.create"},
        "claim_type": "ledger_export",
        "canonical_source_required": True,
        "export_controls_required": True,
    },
    "ledger.bank_connection.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_ops", "finance_manager", "super_admin"},
        "scopes": {"finance.reconciliation.write"},
        "claim_type": "settlement",
        "canonical_source_required": True,
    },
    "ledger.bank_connection.sync": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_ops", "finance_manager", "super_admin"},
        "scopes": {"finance.reconciliation.write"},
        "claim_type": "settlement",
        "canonical_source_required": True,
    },
    "ledger.reconciliation.match": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_ops", "finance_manager", "accountant", "super_admin"},
        "scopes": {"finance.reconciliation.write"},
        "claim_type": "settlement",
        "canonical_source_required": True,
    },
    "ledger.reconciliation.review": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_manager", "accountant", "super_admin"},
        "scopes": {"finance.reconciliation.review"},
        "claim_type": "ledger",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "ledger.reconciliation.close": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_ops", "finance_manager", "accountant", "super_admin"},
        "scopes": {"finance.close.write"},
        "claim_type": "ledger",
        "canonical_source_required": True,
    },
    "ledger.reconciliation.correction": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_ops", "finance_manager", "accountant", "super_admin"},
        "scopes": {"finance.close.write"},
        "claim_type": "ledger",
        "canonical_source_required": True,
    },
    "payments.provider_event.record": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"payment_ops", "finance_ops", "super_admin"},
        "scopes": {"payment.provider_event.write"},
        "claim_type": "payment_status",
        "adapter_evidence_allowed": True,
    },
    "payments.payer.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"payment_ops", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"payment.payer.write"},
        "claim_type": "payment",
        "canonical_source_required": True,
    },
    "payments.bill.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"payment_ops", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"payment.bill.write"},
        "claim_type": "payment",
        "canonical_source_required": True,
    },
    "payments.intent.create": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"tenant", "member", "parent", "student", "guardian", "payment_ops", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"payment.intent.write"},
        "claim_type": "payment",
        "canonical_source_required": True,
    },
    "payments.refund.request": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"payment_ops", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"payment.refund.request"},
        "claim_type": "payment_refund",
        "canonical_source_required": True,
    },
    "payments.refund.transition": {
        "owner": "LiveUIN TrustPay/LiveLedger",
        "roles": {"finance_manager", "super_admin"},
        "scopes": {"payment.refund.review"},
        "claim_type": "payment_refund",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "payments.risk.signal": {
        "owner": "LiveUIN Finance Risk/Identity/Case",
        "roles": {"finance_ops", "finance_manager", "super_admin"},
        "scopes": {"payment.risk.write"},
        "claim_type": "payment_refund",
        "canonical_source_required": True,
    },
    "payments.risk.review": {
        "owner": "LiveUIN Finance Risk/Identity/Case",
        "roles": {"finance_manager", "super_admin"},
        "scopes": {"payment.risk.review"},
        "claim_type": "payment_refund",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "improvement.snapshot.generate": {
        "owner": "LiveUIN Analytics / Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "analytics_ops", "operator_manager", "super_admin"},
        "scopes": {"ops.improvement.write"},
        "claim_type": "improvement",
        "canonical_source_required": True,
    },
    "improvement.snapshot.transition": {
        "owner": "LiveUIN Analytics / Ops / Resolution OS",
        "roles": {"ops_manager", "analytics_ops", "operator_manager", "super_admin"},
        "scopes": {"ops.improvement.write"},
        "claim_type": "improvement",
        "canonical_source_required": True,
    },
    "remediation.holdback.create": {
        "owner": "LiveUIN Ops / Vendor Ops / Property Finance",
        "roles": {"ops_manager", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"vendor_finance.holdback.write"},
        "claim_type": "remediation",
        "canonical_source_required": True,
    },
    "remediation.holdback.transition": {
        "owner": "LiveUIN Ops / Vendor Ops / Property Finance",
        "roles": {"ops_manager", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"vendor_finance.holdback.write"},
        "claim_type": "remediation",
        "canonical_source_required": True,
    },
    "remediation.holdback.release": {
        "owner": "LiveUIN Ops / Vendor Ops / Property Finance",
        "roles": {"ops_manager", "finance_manager", "super_admin"},
        "scopes": {"vendor_finance.holdback.release"},
        "claim_type": "remediation",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "remediation.entry.create": {
        "owner": "LiveUIN Ops / Vendor Ops / Property Finance",
        "roles": {"ops", "ops_manager", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"vendor_finance.remediation.write"},
        "claim_type": "remediation",
        "canonical_source_required": True,
    },
    "remediation.entry.transition": {
        "owner": "LiveUIN Ops / Vendor Ops / Property Finance",
        "roles": {"ops_manager", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"vendor_finance.remediation.write"},
        "claim_type": "remediation",
        "canonical_source_required": True,
    },
    "inventory.offer.upsert": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.offer.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.listing_mapping.create": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.listing_mapping.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.listing_mapping.replace": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.listing_mapping.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.listing_mapping.revoke": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.listing_mapping.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.listing_handoff.issue": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.listing_mapping.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.listing_handoff.resolve": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.listing_mapping.resolve"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.sync.import": {
        "owner": "LiveUIN Inventory / Connect",
        "roles": {"connector_admin", "ops_manager", "super_admin"},
        "scopes": {"inventory.sync.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.sync.review": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.sync.review"},
        "claim_type": "inventory",
        "canonical_source_required": True,
    },
    "inventory.reconciliation.disposition": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.reconciliation.disposition.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "inventory.reconciliation.resolve": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.reconciliation.resolve.write"},
        "claim_type": "inventory",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "inventory.provenance.review": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.provenance.write"},
        "claim_type": "inventory",
        "canonical_source_required": False,
    },
    "inventory.hierarchy.write": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.hierarchy.write"},
        "claim_type": "inventory_hierarchy",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "inventory.hierarchy.review": {
        "owner": "LiveUIN Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.hierarchy.review"},
        "claim_type": "inventory_hierarchy",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "inventory.rental_rule.write": {
        "owner": "LiveUIN Policy/Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.rental_rule.write"},
        "claim_type": "rental_decision",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "inventory.rental_decision.write": {
        "owner": "LiveUIN Policy/Inventory",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"inventory.rental_decision.write"},
        "claim_type": "rental_decision",
        "canonical_source_required": True,
    },
    "inventory.hold.create": {
        "owner": "LiveUIN Inventory / Booking",
        "roles": {"parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.hold.write"},
        "claim_type": "hold",
        "canonical_source_required": True,
    },
    "inventory.hold.release": {
        "owner": "LiveUIN Inventory / Booking",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.hold.write"},
        "claim_type": "hold",
        "canonical_source_required": True,
    },
    "inventory.hold.book": {
        "owner": "LiveUIN Inventory / Booking",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"inventory.hold.write", "booking.write"},
        "claim_type": "hold",
        "canonical_source_required": True,
    },
    "viewing.slot.upsert": {
        "owner": "LiveUIN Viewing/Scheduler",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"viewing.slot.write"},
        "claim_type": "viewing",
        "canonical_source_required": True,
    },
    "viewing.reservation.create": {
        "owner": "LiveUIN Viewing/Scheduler",
        "roles": {"parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"viewing.reservation.write"},
        "claim_type": "viewing",
        "canonical_source_required": True,
    },
    "viewing.reservation.transition": {
        "owner": "LiveUIN Viewing/Scheduler",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"viewing.reservation.write"},
        "claim_type": "viewing",
        "canonical_source_required": True,
    },
    "booking.create": {
        "owner": "LiveUIN Booking/TrustPay",
        "roles": {"parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"booking.write"},
        "claim_type": "booking",
        "canonical_source_required": True,
    },
    "booking.deposit.create": {
        "owner": "LiveUIN Booking/TrustPay",
        "roles": {"ops", "ops_manager", "payment_ops", "super_admin"},
        "scopes": {"booking.deposit.write"},
        "claim_type": "deposit",
        "canonical_source_required": True,
    },
    "booking.transition": {
        "owner": "LiveUIN Booking/TrustPay",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"booking.write"},
        "claim_type": "booking",
        "canonical_source_required": True,
    },
    "ops.ticket.create": {
        "owner": "LiveUIN Ops",
        "roles": {"parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"ops.ticket.write"},
        "claim_type": "ticket",
        "canonical_source_required": True,
    },
    "ops.ticket.transition": {
        "owner": "LiveUIN Ops",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.ticket.write"},
        "claim_type": "ticket",
        "canonical_source_required": True,
    },
    "ops.task.create": {
        "owner": "LiveUIN Ops",
        "roles": {"ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"ops.task.write"},
        "claim_type": "task",
        "canonical_source_required": True,
    },
    "ops.task.transition": {
        "owner": "LiveUIN Ops",
        "roles": {"ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"ops.task.write"},
        "claim_type": "task",
        "canonical_source_required": True,
    },
    "ops.task.proof.append": {
        "owner": "LiveUIN Ops",
        "roles": {"ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"ops.task.proof.write"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "ops.task.proof.review": {
        "owner": "LiveUIN Ops",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.task.proof.review"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "vendor.job.proof.append": {
        "owner": "LiveUIN Ops / Vendor Runtime",
        "roles": {"vendor"},
        "scopes": {"vendor.job.proof.write"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "vendor.job.accept": {
        "owner": "LiveUIN Ops / Vendor Runtime",
        "roles": {"vendor"},
        "scopes": {"vendor.job.accept"},
        "claim_type": "task",
        "canonical_source_required": True,
    },
    "vendor.claim.create": {
        "owner": "LiveUIN Ops / Vendor Runtime",
        "roles": {"vendor"},
        "scopes": {"vendor.claim.write"},
        "claim_type": "payment",
        "canonical_source_required": True,
    },
    "vendor.claim.review": {
        "owner": "LiveUIN Ops / Vendor Runtime",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"ops.task.proof.review"},
        "claim_type": "payment",
        "canonical_source_required": True,
    },
    "ops.resolution.maintenance_intake.create": {
        "owner": "LiveUIN Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.resolution.write", "ops.ticket.write", "ops.task.write"},
        "claim_type": "resolution",
        "canonical_source_required": True,
    },
    "ops.resolution.dispute_intake.create": {
        "owner": "LiveUIN Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.resolution.write", "ops.ticket.write", "ops.task.write"},
        "claim_type": "resolution",
        "canonical_source_required": True,
    },
    "ops.resolution.dispute_pack.create": {
        "owner": "LiveUIN Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.resolution.write"},
        "claim_type": "resolution",
        "canonical_source_required": True,
    },
    "ops.resolution.dispute_pack.evidence.append": {
        "owner": "LiveUIN Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.resolution.write"},
        "claim_type": "resolution",
        "adapter_evidence_allowed": True,
    },
    "ops.resolution.playbook.create": {
        "owner": "LiveUIN Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.resolution.write"},
        "claim_type": "resolution",
        "canonical_source_required": True,
    },
    "ops.resolution.playbook.transition": {
        "owner": "LiveUIN Ops / Resolution OS",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.resolution.write"},
        "claim_type": "resolution",
        "canonical_source_required": True,
    },
    "platform.country_rules.pack.write": {
        "owner": "LiveUIN Platform",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"platform.country_rules.write"},
        "claim_type": "platform_policy",
        "canonical_source_required": True,
    },
    "platform.country_rules.pack.activate": {
        "owner": "LiveUIN Platform",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"platform.country_rules.activate"},
        "claim_type": "platform_policy",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "compliance.publish_gate.create": {
        "owner": "LiveUIN Compliance",
        "roles": {"ops", "ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.compliance.publish.write"},
        "claim_type": "compliance",
        "canonical_source_required": True,
    },
    "compliance.publish_gate.review": {
        "owner": "LiveUIN Compliance",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.compliance.publish.review"},
        "claim_type": "compliance",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "compliance.shared_housing.assess": {
        "owner": "LiveUIN Compliance",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.compliance.marketplace.review"},
        "claim_type": "compliance",
        "canonical_source_required": True,
    },
    "pass.family.read": {
        "owner": "LiveUIN Core/Trust/Ops",
        "roles": {"parent", "student", "guardian", "ops", "super_admin"},
        "scopes": {"pass.case.read"},
        "claim_type": "case",
        "allowed_record_scopes": {"own_case", "household_case", "assigned_case", "global_admin"},
    },
    "verification.profile.create": {
        "owner": "LiveUIN Trust / Identity",
        "roles": {"student", "parent", "guardian", "agent", "ops", "ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.verification.write"},
        "claim_type": "verification",
        "canonical_source_required": True,
    },
    "verification.evidence.append": {
        "owner": "LiveUIN Trust / Identity",
        "roles": {"student", "parent", "guardian", "agent", "ops", "ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.verification.evidence.write"},
        "claim_type": "verification",
        "adapter_evidence_allowed": True,
    },
    "verification.provider_callback.record": {
        "owner": "LiveUIN Trust / Identity",
        "roles": {"ops", "ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.verification.evidence.write"},
        "claim_type": "verification",
        "adapter_evidence_allowed": True,
    },
    "verification.profile.review": {
        "owner": "LiveUIN Trust / Identity",
        "roles": {"ops", "ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.verification.review"},
        "claim_type": "verification",
        "canonical_source_required": True,
    },
    "trust.room_passport.upsert": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.room_passport.write"},
        "claim_type": "room_passport",
        "canonical_source_required": True,
    },
    "trust.evidence.append": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.evidence.write"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "trust.evidence.record": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.evidence.record"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "trust.evidence.review": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.evidence.review"},
        "claim_type": "proof",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "trust.verification.reconcile": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.verification.reconcile"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "trust.verification.read": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.verification.read"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "trust.room_passport.review": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.review"},
        "claim_type": "room_passport",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "trust.candidate.submit": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "media_auth_service", "super_admin"},
        "scopes": {"trust.candidate.submit"},
        "claim_type": "proof",
        "canonical_source_required": True,
    },
    "trust.candidate.review": {
        "owner": "LiveUIN Trust",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"trust.candidate.review"},
        "claim_type": "proof",
        "canonical_source_required": True,
        "maker_checker": True,
    },
    "movein.readiness_card.upsert": {
        "owner": "LiveUIN Booking / Trust / Ops",
        "roles": {"ops", "ops_manager", "booking_ops", "trust_reviewer", "operator", "super_admin"},
        "scopes": {"movein.readiness.write"},
        "claim_type": "move_in",
        "canonical_source_required": True,
    },
    "movein.readiness_card.transition": {
        "owner": "LiveUIN Booking / Trust / Ops",
        "roles": {"ops", "ops_manager", "booking_ops", "operator", "super_admin"},
        "scopes": {"movein.readiness.write"},
        "claim_type": "move_in",
        "canonical_source_required": True,
    },
    "lifecycle.checkin.create": {
        "owner": "LiveUIN Ops / Lifecycle",
        "roles": {"tenant", "member", "student", "parent", "guardian", "ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"lifecycle.checkin.write"},
        "claim_type": "lifecycle",
        "canonical_source_required": True,
    },
    "lifecycle.review.create": {
        "owner": "LiveUIN Ops / Lifecycle",
        "roles": {"tenant", "member", "student", "parent", "guardian", "ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"lifecycle.review.write"},
        "claim_type": "lifecycle",
        "canonical_source_required": True,
    },
    "lifecycle.record.transition": {
        "owner": "LiveUIN Ops / Lifecycle",
        "roles": {"ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"lifecycle.record.write"},
        "claim_type": "lifecycle",
        "canonical_source_required": True,
    },
    "demand.intake.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "agent", "connector_admin", "super_admin"},
        "scopes": {"demand.intake.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.channel_callback.record": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.attribution.write"},
        "claim_type": "demand",
        "adapter_evidence_allowed": True,
    },
    "demand.media_pack.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "agent", "connector_admin", "super_admin"},
        "scopes": {"demand.media.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.run.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"demand.run.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.ai_session.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.ai.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.content_pack.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.content.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.listing_assist.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops", "ops_manager", "agent", "connector_admin", "super_admin"},
        "scopes": {"demand.listing_assist.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.listing_assist.review": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops_manager", "super_admin"},
        "scopes": {"demand.review.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.content_pack.review": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops_manager", "super_admin"},
        "scopes": {"demand.review.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.run.preflight": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.preflight.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.share_pack.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "content_reviewer", "ops_manager", "super_admin"},
        "scopes": {"demand.share.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.lead_passport.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "agent", "connector_admin", "super_admin"},
        "scopes": {"demand.lead.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.request.create": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "agent", "connector_admin", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "adapter_evidence_allowed": True,
    },
    "demand.request.verify": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.request.expire": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.request.close": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.attribution.correct": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.attribution.write"},
        "claim_type": "demand_attribution",
        "canonical_source_required": True,
    },
    "demand.attribution.dispute": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.attribution.write"},
        "claim_type": "demand_attribution",
        "canonical_source_required": True,
    },
    "demand.spine_evidence.read": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.spine.read"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.explanation.read": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops_manager", "super_admin", "parent", "student", "guardian"},
        "scopes": {"demand.explanation.read"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.supply_state.read": {
        "owner": "LiveUIN Demand Ops",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.supply_state.read"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.supply_state.write": {
        "owner": "LiveUIN Demand Ops",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.supply_state.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.policy.read": {
        "owner": "LiveUIN Core Demand/Policy",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.policy.read"},
        "claim_type": "demand_policy",
        "canonical_source_required": True,
    },
    "demand.policy.write": {
        "owner": "LiveUIN Core Demand/Policy",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.policy.write"},
        "claim_type": "demand_policy",
        "canonical_source_required": True,
    },
    "demand.quality.read": {
        "owner": "LiveUIN Intelligence/Analytics",
        "roles": {"analytics_ops", "demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.quality.read"},
        "claim_type": "demand_quality_metric",
        "canonical_source_required": True,
    },
    "demand.quality.write": {
        "owner": "LiveUIN Intelligence/Analytics",
        "roles": {"analytics_ops", "demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.quality.write"},
        "claim_type": "demand_quality_metric",
        "canonical_source_required": True,
    },
    "demand.pairing.generate": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.pairing.shortlist": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.pairing.reject": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.pairing.accept": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.request.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.explanation.override": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops_manager", "super_admin"},
        "scopes": {"demand.explanation.override"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.routing_rule.upsert": {
        "owner": "LiveUIN Demand OS",
        "roles": {"connector_admin", "ops_manager", "super_admin"},
        "scopes": {"demand.routing.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "demand.lead.assign": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"demand.assignment.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "owner.contact.upsert": {
        "owner": "LiveUIN Owner Ops Runtime",
        "roles": {"owner", "landlord", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"owner.contact.write"},
        "claim_type": "owner_contact",
        "canonical_source_required": True,
    },
    "contract.template.upsert": {
        "owner": "LiveUIN ContractOps Runtime",
        "roles": {"owner", "landlord", "agent", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"contract.template.write"},
        "claim_type": "contract_template",
        "canonical_source_required": True,
    },
    "contract.draft.upsert": {
        "owner": "LiveUIN Contract Builder Runtime",
        "roles": {"owner", "landlord", "agent", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"contract.draft.write"},
        "claim_type": "contract_draft",
        "canonical_source_required": True,
    },
    "contract.execution.upsert": {
        "owner": "LiveUIN Contract Execution Runtime",
        "roles": {"owner", "landlord", "agent", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"contract.execution.write"},
        "claim_type": "contract_execution",
        "canonical_source_required": True,
    },
    "agreement.precommit.read": {
        "owner": "LiveUIN Partner/Host/Case/Agreement",
        "roles": {"parent", "guardian", "student", "tenant", "member", "ops", "ops_manager", "owner", "finance", "finance_manager", "super_admin"},
        "scopes": {"agreement.precommit.read"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "agreement.precommit.write": {
        "owner": "LiveUIN Partner/Host/Case/Agreement",
        "roles": {"ops", "ops_manager", "owner", "finance", "finance_manager", "super_admin"},
        "scopes": {"agreement.precommit.write"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "agreement.precommit.acknowledge": {
        "owner": "LiveUIN Partner/Host/Case/Agreement",
        "roles": {"parent", "guardian", "student", "tenant", "member", "ops", "ops_manager", "super_admin"},
        "scopes": {"agreement.precommit.acknowledge"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "agreement.precommit.commitment_check": {
        "owner": "LiveUIN Partner/Host/Case/Agreement",
        "roles": {"parent", "guardian", "student", "tenant", "member", "ops", "ops_manager", "owner", "finance", "finance_manager", "super_admin"},
        "scopes": {"agreement.precommit.read"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "agreement.lifecycle.read": {
        "owner": "LiveUIN Agreement/Vault",
        "roles": {"parent", "guardian", "student", "tenant", "member", "ops", "ops_manager", "owner", "finance", "finance_manager", "super_admin"},
        "scopes": {"agreement.lifecycle.read"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "agreement.lifecycle.write": {
        "owner": "LiveUIN Agreement/Vault",
        "roles": {"ops", "ops_manager", "owner", "finance", "finance_manager", "super_admin"},
        "scopes": {"agreement.lifecycle.write"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "agreement.lifecycle.sign": {
        "owner": "LiveUIN Agreement/Vault",
        "roles": {"parent", "guardian", "student", "tenant", "member", "ops", "ops_manager", "owner", "finance", "finance_manager", "super_admin"},
        "scopes": {"agreement.lifecycle.sign"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "support.profile.upsert": {
        "owner": "LiveUIN Support Runtime",
        "roles": {"owner", "landlord", "agent", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"support.profile.write"},
        "claim_type": "support_profile",
        "canonical_source_required": True,
    },
    "support.request.create": {
        "owner": "LiveUIN Support Runtime",
        "roles": {"parent", "student", "guardian", "owner", "landlord", "agent", "ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"support.request.write"},
        "claim_type": "ticket",
        "canonical_source_required": True,
    },
    "support.request.transition": {
        "owner": "LiveUIN Support Runtime",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"support.request.write"},
        "claim_type": "ticket",
        "canonical_source_required": True,
    },
    "service_claim.definition.write": {
        "owner": "LiveUIN service-policy/claims registry",
        "roles": {"ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"service.claim.write"},
        "claim_type": "service_claim",
        "canonical_source_required": True,
    },
    "service_claim.capacity.write": {
        "owner": "LiveUIN service-policy/claims registry",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"service.claim.capacity.write"},
        "claim_type": "service_claim",
        "canonical_source_required": True,
    },
    "service_claim.read": {
        "owner": "LiveUIN service-policy/claims registry",
        "roles": {"ops", "ops_manager", "trust_reviewer", "super_admin"},
        "scopes": {"service.claim.read"},
        "claim_type": "service_claim",
        "canonical_source_required": True,
    },
    "case.parent_update.write": {
        "owner": "LiveUIN Case/Consent/Communications",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"case.parent_update.write"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "case.parent_update.read": {
        "owner": "LiveUIN Case/Consent/Communications",
        "roles": {"parent", "guardian", "student", "tenant", "member", "ops", "ops_manager", "super_admin"},
        "scopes": {"case.parent_update.read"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "case.communication.write": {
        "owner": "LiveUIN Communications/Consent",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"case.communication.write"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "case.communication.read": {
        "owner": "LiveUIN Communications/Consent",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"case.communication.read"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "case.moveout_closure.write": {
        "owner": "LiveUIN Case/Resolution/Finance",
        "roles": {"ops", "ops_manager", "finance", "finance_manager", "super_admin"},
        "scopes": {"case.moveout_closure.write"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "case.moveout_closure.read": {
        "owner": "LiveUIN Case/Resolution/Finance",
        "roles": {"ops", "ops_manager", "finance", "finance_manager", "super_admin"},
        "scopes": {"case.moveout_closure.read"},
        "claim_type": "case",
        "canonical_source_required": True,
    },
    "living.saved_search.upsert": {
        "owner": "LiveUIN Living Runtime",
        "roles": {"tenant", "member", "parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"living.saved_search.write"},
        "claim_type": "living_saved_search",
        "canonical_source_required": True,
    },
    "living.application.upsert": {
        "owner": "LiveUIN Application Locker Runtime",
        "roles": {"tenant", "member", "parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"living.application.write"},
        "claim_type": "living_application",
        "canonical_source_required": True,
    },
    "demand.operator_queue.transition": {
        "owner": "LiveUIN Demand OS",
        "roles": {"demand_ops", "ops", "ops_manager", "super_admin"},
        "scopes": {"demand.queue.write"},
        "claim_type": "demand",
        "canonical_source_required": True,
    },
    "connector.case.handoff": {
        "owner": "LiveUIN Core",
        "roles": {"connector_admin", "ops", "super_admin"},
        "scopes": {"connect.case.handoff"},
        "claim_type": "case",
        "connector_transport_only": True,
    },
    "partner.offer.upsert": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"connector_admin", "ops", "ops_manager", "super_admin"},
        "scopes": {"connect.offer.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "partner.contact.upsert": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"agent", "connector_admin", "ops", "ops_manager", "super_admin"},
        "scopes": {"partner.contact.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.reminder.create": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"agent", "connector_admin", "ops", "ops_manager", "super_admin"},
        "scopes": {"partner.reminder.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.hierarchy.upsert": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"connector_admin", "ops", "ops_manager", "super_admin"},
        "scopes": {"partner.hierarchy.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.commission_rule.upsert": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"connector_admin", "ops", "ops_manager", "finance_manager", "super_admin"},
        "scopes": {"partner.commission.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.payout_eligibility.write": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"connector_admin", "ops", "ops_manager", "finance_ops", "finance_manager", "super_admin"},
        "scopes": {"partner.payout.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.payout_eligibility.review": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"ops_manager", "finance_manager", "super_admin"},
        "scopes": {"partner.payout.review"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.payout_eligibility.read": {
        "owner": "LiveUIN Partner/Core",
        "roles": {"ops", "ops_manager", "finance_ops", "finance_manager", "super_admin", "connector_admin"},
        "scopes": {"partner.payout.read"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.authority.write": {
        "owner": "LiveUIN Partner/Identity/Ops",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"partner.authority.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.authority.read": {
        "owner": "LiveUIN Partner/Identity/Ops",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"partner.authority.read"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.governance.write": {
        "owner": "LiveUIN Legal/Partner governance",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"partner.governance.write"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "partner.governance.read": {
        "owner": "LiveUIN Legal/Partner governance",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"partner.governance.read"},
        "claim_type": "partner",
        "canonical_source_required": True,
    },
    "ops.assignment.write": {
        "owner": "LiveUIN Ops/Vendor",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"ops.assignment.write"},
        "claim_type": "task",
        "canonical_source_required": True,
    },
    "ops.assignment.read": {
        "owner": "LiveUIN Ops/Vendor",
        "roles": {"ops", "ops_manager", "operator", "super_admin"},
        "scopes": {"ops.assignment.read"},
        "claim_type": "task",
        "canonical_source_required": True,
    },
    "ops.queue.runbook.write": {
        "owner": "LiveUIN Ops queues",
        "roles": {"ops_manager", "super_admin"},
        "scopes": {"ops.queue.runbook.write"},
        "claim_type": "ops_queue",
        "canonical_source_required": True,
    },
    "ops.queue.runbook.read": {
        "owner": "LiveUIN Ops queues",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.queue.runbook.read"},
        "claim_type": "ops_queue",
        "canonical_source_required": True,
    },
    "ops.queue.route.write": {
        "owner": "LiveUIN Ops queues",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.queue.route.write"},
        "claim_type": "ops_queue",
        "canonical_source_required": True,
    },
    "ops.queue.route.read": {
        "owner": "LiveUIN Ops queues",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.queue.route.read"},
        "claim_type": "ops_queue",
        "canonical_source_required": True,
    },
    "marketplace.offer.upsert": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"vendor", "connector_admin", "ops", "ops_manager", "super_admin"},
        "scopes": {"vendor.offer.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.offer.interest": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"tenant", "member", "parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"marketplace.request.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.offer.redeem_intent": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"tenant", "member", "parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"marketplace.request.write", "vendor.request.write", "ops.ticket.write", "ops.task.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.group_deal.join": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"tenant", "member", "parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"marketplace.request.write", "community.group.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.offer.approve": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.marketplace.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.offer.reject": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.marketplace.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.offer.publish": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.marketplace.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.offer.unpublish": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "super_admin"},
        "scopes": {"ops.marketplace.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.request.dispute": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"tenant", "member", "parent", "student", "guardian", "ops", "ops_manager", "super_admin"},
        "scopes": {"marketplace.request.write", "vendor.request.write", "ops.resolution.write"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.request.refund_request": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "payment_ops", "super_admin"},
        "scopes": {"ops.marketplace.write", "payment.refund.request"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.request.resolve": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "payment_ops", "super_admin"},
        "scopes": {"ops.marketplace.write", "vendor.request.write", "payment.refund.review"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.reward.grant": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "payment_ops", "finance_manager", "super_admin"},
        "scopes": {"ops.marketplace.write", "payment.refund.review"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "marketplace.reward.transition": {
        "owner": "LiveUIN Marketplace Layer",
        "roles": {"ops", "ops_manager", "payment_ops", "finance_manager", "super_admin"},
        "scopes": {"ops.marketplace.write", "payment.refund.review"},
        "claim_type": "marketplace",
        "canonical_source_required": True,
    },
    "intelligence.event.record": {
        "owner": "LiveUIN Intelligence",
        "roles": {"analyst", "demand_ops", "ops", "super_admin"},
        "scopes": {"intelligence.event.write"},
        "claim_type": "intelligence",
        "adapter_evidence_allowed": True,
    },
    "intelligence.source.register": {
        "owner": "LiveUIN Intelligence",
        "roles": {"analyst", "demand_ops", "ops_manager", "super_admin"},
        "scopes": {"intelligence.source.write"},
        "claim_type": "intelligence",
        "canonical_source_required": True,
    },
    "team.note.append": {
        "owner": "LiveUIN Team Notes Runtime",
        "roles": {"ops", "ops_manager", "connector_admin", "super_admin"},
        "scopes": {"team.note.write"},
        "claim_type": "team_note",
        "canonical_source_required": True,
    },
}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _clean_id(value: Any, max_length: int = 96) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]", "", str(value or "").strip())
    return cleaned[:max_length]


def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]", "_", str(value or "").strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return (cleaned or default)[:max_length]


def _workspace_id(value: Any = "") -> str:
    return _clean_id(value or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _clean_list(value: Any, *, slug: bool = False, max_length: int = 120) -> List[str]:
    cleaned: List[str] = []
    for item in _as_list(value):
        text = _clean_slug(item, "", max_length) if slug else _clean_id(item, max_length)
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def _condition_source(payload: Dict[str, Any]) -> Dict[str, Any]:
    return _as_dict(payload.get("conditions"))


def _condition_value(payload: Dict[str, Any], key: str, default: Any = "") -> Any:
    conditions = _condition_source(payload)
    return payload.get(key) if key in payload else conditions.get(key, default)


def _authority_basis(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw = _condition_value(payload, "authority_basis", {})
    basis = _as_dict(raw)
    if not basis:
        basis = {
            "type": _clean_slug(_condition_value(payload, "authority_type", ""), "", 80),
            "state": _clean_slug(_condition_value(payload, "authority_state", ""), "", 80),
            "evidence_ref": _clean_id(_condition_value(payload, "authority_evidence_ref", ""), 160),
            "jurisdiction": _clean_slug(_condition_value(payload, "authority_jurisdiction", ""), "", 80),
            "expires_at": int(_condition_value(payload, "authority_expires_at", 0) or 0),
        }
    return {
        "type": _clean_slug(basis.get("type") or basis.get("basis_type"), "", 80),
        "state": _clean_slug(basis.get("state") or basis.get("authority_state"), "missing", 80),
        "evidence_ref": _clean_id(basis.get("evidence_ref") or basis.get("authority_evidence_ref"), 160),
        "jurisdiction": _clean_slug(basis.get("jurisdiction"), "", 80),
        "expires_at": int(basis.get("expires_at") or 0),
        "verified_by": _clean_id(basis.get("verified_by"), 120),
    }


def _delegation(payload: Dict[str, Any]) -> Dict[str, Any]:
    delegation = _as_dict(_condition_value(payload, "delegation", {}))
    return {
        "delegated_by": _clean_id(delegation.get("delegated_by") or _condition_value(payload, "delegated_by", ""), 120),
        "delegated_to": _clean_id(delegation.get("delegated_to") or _condition_value(payload, "delegated_to", ""), 120),
        "state": _clean_slug(delegation.get("state") or _condition_value(payload, "delegation_state", ""), "", 80),
        "expires_at": int(delegation.get("expires_at") or _condition_value(payload, "delegation_expires_at", 0) or 0),
    }


def _g08_g09_conditions(payload: Dict[str, Any], *, grant_id: str, status: str, consent_state: str, now: int) -> Dict[str, Any]:
    conditions = _condition_source(payload)
    consent_version = _clean_id(_condition_value(payload, "consent_version", ""), 80)
    grant_version = _clean_id(_condition_value(payload, "grant_version", ""), 80) or consent_version or ("grant-v1-" + grant_id[-12:])
    recipients = _clean_list(_condition_value(payload, "recipients", []), slug=False, max_length=120)
    visibility_fields = _clean_list(_condition_value(payload, "visibility_fields", []), slug=True, max_length=120)
    purpose = _clean_slug(_condition_value(payload, "purpose", ""), "", 120)
    disclosure_model = _clean_slug(_condition_value(payload, "disclosure_model", ""), "", 120)
    withdrawal = _as_dict(_condition_value(payload, "withdrawal", {}))
    dispute = _as_dict(_condition_value(payload, "dispute", {}))
    supersession = _as_dict(_condition_value(payload, "supersession", {}))
    authority = _authority_basis(payload)
    return _redact(
        {
            **conditions,
            "matrix_version": "G08_G09_PARTICIPANT_AUTHORITY_VISIBILITY_CONSENT_MATRIX_v1.0.0",
            "interface_version": _clean_id(_condition_value(payload, "interface_version", "ECC-PARTICIPANT-GRANT-v1"), 80) or "ECC-PARTICIPANT-GRANT-v1",
            "grant_version": grant_version,
            "visibility_fields": visibility_fields,
            "purpose": purpose,
            "consent_version": consent_version,
            "consent_state": consent_state,
            "withdrawal_state": _clean_slug(_condition_value(payload, "withdrawal_state", conditions.get("withdrawal_state", "not_withdrawn")), "not_withdrawn", 80),
            "recipients": recipients,
            "disclosure_model": disclosure_model,
            "authority_basis": authority,
            "delegation": _delegation(payload),
            "withdrawal": {
                "state": _clean_slug(withdrawal.get("state") or _condition_value(payload, "withdrawal_state", "not_withdrawn"), "not_withdrawn", 80),
                "version": _clean_id(withdrawal.get("version") or consent_version, 80),
                "at": int(withdrawal.get("at") or _condition_value(payload, "withdrawn_at", 0) or 0),
                "reason": _clean_slug(withdrawal.get("reason") or _condition_value(payload, "withdrawal_reason", ""), "", 120),
            },
            "dispute": {
                "state": _clean_slug(dispute.get("state") or _condition_value(payload, "dispute_state", "none"), "none", 80),
                "case_ref": _clean_id(dispute.get("case_ref") or _condition_value(payload, "dispute_case_ref", ""), 160),
                "opened_at": int(dispute.get("opened_at") or _condition_value(payload, "dispute_opened_at", 0) or 0),
            },
            "supersession": {
                "supersedes_grant_id": _clean_id(supersession.get("supersedes_grant_id") or _condition_value(payload, "supersedes_grant_id", ""), 140),
                "superseded_by_grant_id": _clean_id(supersession.get("superseded_by_grant_id") or _condition_value(payload, "superseded_by_grant_id", ""), 140),
                "superseded_at": int(supersession.get("superseded_at") or _condition_value(payload, "superseded_at", 0) or 0),
            },
            "issued_at": int(_condition_value(payload, "issued_at", now) or now),
            "effective_at": int(_condition_value(payload, "effective_at", now) or now),
        }
    )


def _conditions_complete_for_active(conditions: Dict[str, Any]) -> str:
    if not str(conditions.get("consent_version") or "").strip():
        return "consent_version_required"
    if not str(conditions.get("purpose") or "").strip():
        return "purpose_required"
    if not _as_list(conditions.get("recipients")):
        return "recipient_required"
    if not str(conditions.get("disclosure_model") or "").strip():
        return "disclosure_model_required"
    if not _as_list(conditions.get("visibility_fields")):
        return "visibility_fields_required"
    authority = _as_dict(conditions.get("authority_basis"))
    if _clean_slug(authority.get("state"), "missing", 80) not in AUTHORITY_ACTIVE_STATES:
        return "authority_basis_required"
    if not _clean_slug(authority.get("type"), "", 80):
        return "authority_basis_required"
    return ""


def _exceptional_authority_condition_mismatch(payload: Dict[str, Any], grant: Dict[str, Any], now: int) -> str:
    conditions = _as_dict(grant.get("conditions"))
    authority = _as_dict(conditions.get("authority_basis"))
    provenance = _as_dict(grant.get("provenance"))
    decision_id = _clean_id(
        conditions.get("authority_decision_id")
        or authority.get("evidence_ref")
        or provenance.get("authority_decision_id")
        or provenance.get("decision_id"),
        160,
    )
    if not decision_id or not decision_id.startswith("exa_dec_"):
        return ""
    try:
        try:
            from . import core_exceptional_authority_store as exceptional_store
        except ImportError:  # pragma: no cover - supports direct script execution.
            import core_exceptional_authority_store as exceptional_store
    except Exception:
        return "participant_authority_decision_unavailable"

    workspace_id = _workspace_id(grant.get("workspace_id") or payload.get("workspace_id"))
    decision = exceptional_store.get_decision(workspace_id, decision_id)
    if not decision:
        return "participant_authority_decision_unavailable"
    status = _clean_slug(decision.get("status"), "", 80)
    if status != "verified":
        return f"participant_authority_{status or 'not_active'}"
    if _clean_id(decision.get("workspace_id"), 96) != workspace_id:
        return "participant_authority_workspace_mismatch"
    if _clean_id(decision.get("case_id"), 120) != _clean_id(grant.get("case_id"), 120):
        return "participant_authority_case_mismatch"
    if _clean_id(decision.get("subject_person_id"), 120) != _clean_id(grant.get("participant_id"), 120):
        return "participant_authority_subject_mismatch"
    expires_at = int(decision.get("expires_at") or 0)
    if expires_at and expires_at <= now:
        return "participant_authority_expired"
    action = _clean_slug(payload.get("action"), "pass.read", 120)
    allowed_actions = {_clean_slug(item, "", 120) for item in _as_list(decision.get("allowed_actions"))}
    if action and action not in allowed_actions:
        return "participant_authority_action_mismatch"
    decision_conditions = _as_dict(decision.get("conditions"))
    for field in ("purpose", "recipient", "visibility", "disclosure_model"):
        expected = _clean_slug(decision_conditions.get(field), "", 120)
        actual = _clean_slug(conditions.get(field), "", 120)
        if expected and actual != expected:
            return f"participant_authority_{field}_mismatch"
    return ""


def _requested_condition_mismatches(payload: Dict[str, Any], grant: Dict[str, Any], now: int) -> str:
    conditions = _as_dict(grant.get("conditions"))
    requested_purpose = _clean_slug(payload.get("purpose") or _as_dict(payload.get("conditions")).get("purpose"), "", 120)
    if requested_purpose and requested_purpose != _clean_slug(conditions.get("purpose"), "", 120):
        return "participant_grant_purpose_mismatch"
    requested_recipient = _clean_id(payload.get("recipient") or payload.get("recipient_id") or _as_dict(payload.get("conditions")).get("recipient"), 120)
    requested_recipients = _clean_list(payload.get("recipients") or _as_dict(payload.get("conditions")).get("recipients"), slug=False, max_length=120)
    if requested_recipient:
        requested_recipients.append(requested_recipient)
    allowed_recipients = {str(item) for item in _as_list(conditions.get("recipients"))}
    if requested_recipients and not set(requested_recipients).issubset(allowed_recipients):
        return "participant_grant_recipient_forbidden"
    requested_disclosure = _clean_slug(payload.get("disclosure_model") or _as_dict(payload.get("conditions")).get("disclosure_model"), "", 120)
    if requested_disclosure and requested_disclosure != _clean_slug(conditions.get("disclosure_model"), "", 120):
        return "participant_grant_disclosure_model_mismatch"
    requested_fields = _clean_list(payload.get("visibility_fields") or payload.get("requested_fields") or _as_dict(payload.get("conditions")).get("visibility_fields"), slug=True, max_length=120)
    allowed_fields = {str(item) for item in _as_list(conditions.get("visibility_fields"))}
    if requested_fields and "*" not in allowed_fields and not set(requested_fields).issubset(allowed_fields):
        return "participant_grant_visibility_forbidden"
    requested_consent_version = _clean_id(payload.get("consent_version") or _as_dict(payload.get("conditions")).get("consent_version"), 80)
    if requested_consent_version and requested_consent_version != _clean_id(conditions.get("consent_version"), 80):
        return "participant_grant_consent_version_mismatch"
    authority = _as_dict(conditions.get("authority_basis"))
    authority_state = _clean_slug(authority.get("state"), "missing", 80)
    authority_expires_at = int(authority.get("expires_at") or 0)
    if authority_state in AUTHORITY_DENIED_STATES or authority_state not in AUTHORITY_ACTIVE_STATES:
        return "participant_authority_not_active"
    if authority_expires_at and authority_expires_at <= now:
        return "participant_authority_expired"
    authority_mismatch = _exceptional_authority_condition_mismatch(payload, grant, now)
    if authority_mismatch:
        return authority_mismatch
    delegation = _as_dict(conditions.get("delegation"))
    delegation_state = _clean_slug(delegation.get("state"), "", 80)
    delegation_expires_at = int(delegation.get("expires_at") or 0)
    if delegation_state in {"withdrawn", "revoked", "expired", "disputed"}:
        return "participant_delegation_not_active"
    if delegation_expires_at and delegation_expires_at <= now:
        return "participant_delegation_expired"
    dispute_state = _clean_slug(_as_dict(conditions.get("dispute")).get("state"), "none", 80)
    if dispute_state and dispute_state not in {"none", "closed", "resolved"}:
        return "participant_authority_disputed"
    withdrawal_state = _clean_slug(conditions.get("withdrawal_state") or _as_dict(conditions.get("withdrawal")).get("state"), "not_withdrawn", 80)
    if withdrawal_state not in {"not_withdrawn", "none"}:
        return "participant_consent_withdrawn"
    if _clean_slug(conditions.get("disclosure_model"), "", 120) not in DISCLOSURE_MODELS:
        return "participant_grant_disclosure_model_unknown"
    return ""


def _normalize_participant_grant_status(status: Any, consent_state: str, conditions: Dict[str, Any]) -> str:
    normalized = _clean_slug(status, "active", 80)
    if normalized == "approved":
        normalized = "active"
    if normalized in {"draft", "v0.1_draft", "v0_1_draft", "v0_1-draft", "v0.1-draft"}:
        normalized = "draft_not_effective"
    if normalized not in PARTICIPANT_GRANT_STATUSES:
        normalized = "draft_not_effective"

    withdrawal_state = _clean_slug(conditions.get("withdrawal_state") or _as_dict(conditions.get("withdrawal")).get("state"), "not_withdrawn", 80)
    dispute_state = _clean_slug(_as_dict(conditions.get("dispute")).get("state"), "none", 80)
    authority_state = _clean_slug(_as_dict(conditions.get("authority_basis")).get("state"), "missing", 80)
    if consent_state == "withdrawn" or withdrawal_state not in {"not_withdrawn", "none"}:
        return "withdrawn"
    if consent_state == "expired":
        return "expired"
    if consent_state in {"declined", "not_consented", "missing"} and normalized in ACTIVE_PARTICIPANT_GRANT_STATUSES:
        return "suspended"
    if dispute_state and dispute_state not in {"none", "closed", "resolved"}:
        return "disputed"
    if authority_state == "disputed":
        return "disputed"
    if authority_state in {"expired", "withdrawn", "revoked", "superseded"}:
        return authority_state
    if normalized in ACTIVE_PARTICIPANT_GRANT_STATUSES:
        blocker = _conditions_complete_for_active(conditions)
        if blocker:
            return "pending_evidence"
    return normalized


def _bounded_limit(value: Any, default: int = 50, high: int = 500) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(1, min(high, number))


def _redact(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if not isinstance(value, dict):
        return value
    cleaned: Dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if key_text.lower() in SENSITIVE_KEYS:
            cleaned[key_text] = "[redacted]"
        else:
            cleaned[key_text] = _redact(item)
    return cleaned


def error(detail: str, status_code: int = 400, **extra: Any) -> Dict[str, Any]:
    return {"ok": False, "detail": detail, "status_code": status_code, **extra}


def _envelope(status: str, workspace_id: str, **payload: Any) -> Dict[str, Any]:
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": status,
        "workspace_id": workspace_id,
        "source": "liveuin_core_access",
        "canonical_owner": CANONICAL_OWNER,
        "routes": {
            "status": "/api/core/access/status",
            "evaluate": "/api/core/access/policies/evaluate",
            "classify_source": "/api/core/access/sources/classify",
            "idempotency_claim": "/api/core/access/idempotency/claims",
            "idempotency_complete": "/api/core/access/idempotency/claims/{idempotency_key}/complete",
            "decisions": "/api/core/access/decisions",
            "source_assessments": "/api/core/access/sources",
            "idempotency_claims": "/api/core/access/idempotency/claims",
            "adapter_replay_nonces": "/api/core/access/adapter-replay-nonces",
            "participant_grants": "/api/core/access/participant-grants",
            "participant_grant_evaluate": "/api/core/access/participant-grants/evaluate",
            "participant_grant_revoke": "/api/core/access/participant-grants/{grant_id}/revoke",
        },
        "boundary": {
            "surface": "Admin, Core APIs, finance review, connector handoff, and internal gateway policy checks",
            "layer": "policy decision, idempotency, adapter replay, and source-governance contract",
            "owner": CANONICAL_OWNER,
            "identity_role": "Consumes LiveUIN Identity/workspace roles and scopes; does not mint identity tokens.",
            "connector_role": "Can authorize handoff transport only; connector records do not become product truth.",
            "wechat_role": "Channel identity/message delivery only.",
            "finance_role": "Enforces finance scopes, maker/checker policy, and export acknowledgements before ledger posting/export.",
            "route_guard_role": "Local preview route guard consumes these decisions before selected high-risk mutations; production gateway enforcement remains.",
            "adapter_replay_role": "Durably reserves signed adapter nonces after signature verification to block exact callback replay.",
            "participant_grant_role": "Durably gates case/pass participant access separately from generic role or channel login state.",
        },
        **payload,
    }


def _grant_actions(value: Any) -> List[str]:
    cleaned: List[str] = []
    for item in _as_list(value):
        action = _clean_slug(item, "", 120)
        if action and action not in cleaned:
            cleaned.append(action)
    return cleaned


def _grant_resources(value: Any) -> List[str]:
    cleaned: List[str] = []
    for item in _as_list(value):
        resource = _clean_id(item, 160) or _clean_slug(item, "", 160)
        if resource and resource not in cleaned:
            cleaned.append(resource)
    return cleaned


def _revocation_propagation(
    *,
    grant: Dict[str, Any],
    revoked_by: str,
    reason: str,
    created_at: int,
) -> Dict[str, Any]:
    return {
        "status": "revocation_required",
        "created_at": created_at,
        "revoked_by": revoked_by,
        "reason": reason,
        "case_id": grant.get("case_id", ""),
        "participant_id": grant.get("participant_id", ""),
        "targets": {
            "pass_access": "revoked",
            "safe_share": "revoked",
            "protected_media": "revoked",
            "viewing_access": "revoked",
            "booking_actions": "blocked",
            "service_account_messages": "blocked",
            "operator_cache": "purge_required",
            "audit_history": "retained",
        },
        "controls": {
            "channel_state_non_canonical": True,
            "browser_state_non_canonical": True,
            "missing_downstream_acknowledgement_fails_closed": True,
        },
    }


def _grant_denial(detail: str, workspace_id: str, **payload: Any) -> Dict[str, Any]:
    return _envelope(
        "participant_grant_denied",
        workspace_id,
        allowed=False,
        decision="deny",
        reason=detail,
        controls={
            "missing_grant_denied": True,
            "role_only_denied": True,
            "share_id_not_a_grant": True,
            "draft_policy_not_effective": True,
        },
        **payload,
    )


def _canonical_owner_for(claim_type: str) -> str:
    return CLAIM_OWNERS.get(claim_type, "LiveUIN Core/Trust/Ops")


def _hash_payload(payload: Any) -> str:
    encoded = json.dumps(payload if payload is not None else {}, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _source_family(payload: Dict[str, Any]) -> str:
    context = _as_dict(payload.get("context"))
    return _clean_slug(
        payload.get("source_family")
        or payload.get("source_system")
        or context.get("source_family")
        or context.get("source_system"),
        "unknown_source",
        120,
    )


def classify_source(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    workspace_id = _workspace_id(payload.get("workspace_id"))
    context = _redact(_as_dict(payload.get("context") or payload.get("metadata")))
    source_family = _source_family(payload)
    source_system = _clean_slug(payload.get("source_system") or source_family, source_family, 120)
    claim_type = _clean_slug(payload.get("claim_type") or context.get("claim_type"), "product_truth", 120)
    intended_owner = str(payload.get("intended_owner") or context.get("intended_owner") or "").strip()
    canonical_owner = _canonical_owner_for(claim_type)

    allowed_as_canonical = False
    allowed_as_evidence = False
    truth_status = "rejected_unknown_source"
    reason = "unknown_source_family"

    if source_family in CANONICAL_SOURCE_FAMILIES:
        allowed_as_canonical = True
        allowed_as_evidence = True
        truth_status = "canonical_source"
        reason = "liveuin_owned_source"
    elif source_family == "liveuin_connect" and claim_type == "connector_setup":
        allowed_as_canonical = True
        allowed_as_evidence = True
        truth_status = "canonical_connector_setup_source"
        reason = "connect_setup_truth_only"
        canonical_owner = "LiveUIN Connect"
    elif source_family in ADAPTER_EVIDENCE_FAMILIES:
        allowed_as_evidence = True
        truth_status = "adapter_evidence_only"
        reason = "adapter_evidence_must_be_normalized_by_liveuin_owner"
    elif source_family in DISPLAY_OR_BRIDGE_FAMILIES:
        truth_status = "display_or_bridge_only"
        reason = "surface_or_channel_not_product_truth"

    if source_family in {"bank_portal", "bank_feed"} and claim_type in {"settlement", "ledger", "ledger_export"}:
        reason = "bank_sources_support_reconciliation_only"
        allowed_as_canonical = False
        allowed_as_evidence = source_family == "bank_feed"
        truth_status = "reconciliation_evidence_only" if source_family == "bank_feed" else "display_or_bridge_only"
    if source_family in {"psp_dashboard", "payment_provider", "psp_webhook"} and claim_type in {"payment", "payment_status", "settlement", "ledger"}:
        allowed_as_canonical = False
        allowed_as_evidence = source_family in {"payment_provider", "psp_webhook"}
        truth_status = "adapter_evidence_only" if allowed_as_evidence else "display_or_bridge_only"
        reason = "psp_sources_must_be_normalized_by_trustpay_liveledger"
    if source_family in {"wechat", "wechat_pay", "wordpress_connector", "liveuin_connector", "laijuzhu_ui", "igema_notes", "operator_chat", "vendor_spreadsheet", "report_export", "ui_export"}:
        allowed_as_canonical = False
        truth_status = "display_or_bridge_only"
        reason = "channel_connector_or_ui_not_canonical_truth"

    assessment_id = _clean_id(payload.get("assessment_id"), 120) or "access_src_" + uuid.uuid4().hex[:16]
    assessment = store.record_source_assessment(
        {
            "assessment_id": assessment_id,
            "workspace_id": workspace_id,
            "source_family": source_family,
            "source_system": source_system,
            "claim_type": claim_type,
            "intended_owner": intended_owner,
            "canonical_owner": canonical_owner,
            "truth_status": truth_status,
            "allowed_as_canonical": allowed_as_canonical,
            "allowed_as_evidence": allowed_as_evidence,
            "reason": reason,
            "controls": {
                "must_handoff_to_canonical_owner": not allowed_as_canonical,
                "adapter_payload_must_be_redacted": source_family in ADAPTER_EVIDENCE_FAMILIES,
                "connector_transport_only": source_family in {"wordpress_connector", "liveuin_connector"},
                "wechat_delivery_only": source_family in {"wechat", "wechat_pay"},
                "payment_execution_performed": False,
                "bank_file_created": False,
            },
            "context": context,
        },
        request_meta,
    )
    return _envelope(
        "source_classified",
        workspace_id,
        source=assessment,
        allowed_as_canonical=assessment.get("allowed_as_canonical") is True,
        allowed_as_evidence=assessment.get("allowed_as_evidence") is True,
        truth_status=assessment.get("truth_status"),
        canonical_owner=canonical_owner,
    )


def _scopes(payload: Dict[str, Any], actor: Dict[str, Any]) -> Set[str]:
    scopes = set()
    for item in _as_list(actor.get("scopes")) + _as_list(payload.get("scopes")):
        cleaned = _clean_slug(item, "", 120)
        if cleaned:
            scopes.add(cleaned)
    return scopes


def _policy_summary(policy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "owner": policy.get("owner", CANONICAL_OWNER),
        "roles": sorted(policy.get("roles", set())),
        "scopes": sorted(policy.get("scopes", set())),
        "claim_type": policy.get("claim_type", "product_truth"),
        "maker_checker": bool(policy.get("maker_checker")),
        "canonical_source_required": bool(policy.get("canonical_source_required")),
        "adapter_evidence_allowed": bool(policy.get("adapter_evidence_allowed")),
        "export_controls_required": bool(policy.get("export_controls_required")),
    }


def _maker_checker_subjects(context: Dict[str, Any]) -> Set[str]:
    subjects = set()
    for key in ("created_by", "prepared_by", "requested_by", "maker_actor_id", "last_updated_by"):
        value = _clean_id(context.get(key), 96)
        if value:
            subjects.add(value)
    return subjects


def evaluate_policy(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    workspace_id = _workspace_id(payload.get("workspace_id"))
    actor = _as_dict(payload.get("actor"))
    resource = _as_dict(payload.get("resource"))
    context = _redact(_as_dict(payload.get("context") or payload.get("metadata")))
    action = _clean_slug(payload.get("action") or context.get("action"), "", 120)
    if not action:
        return error("action_required")

    policy = POLICIES.get(action)
    if not policy:
        return error("unknown_policy_action", 404, action=action)

    actor_id = _clean_id(actor.get("actor_id") or payload.get("actor_id"), 96)
    role = _clean_slug(actor.get("role") or actor.get("persona_role") or payload.get("role"), "", 80)
    provided_scopes = _scopes(payload, actor)
    required_scopes = set(policy.get("scopes", set()))
    source_response = classify_source(
        {
            "workspace_id": workspace_id,
            "source_family": payload.get("source_family") or context.get("source_family") or "liveuin_core",
            "source_system": payload.get("source_system") or context.get("source_system") or payload.get("source_family") or "liveuin_core",
            "claim_type": policy.get("claim_type") or payload.get("claim_type"),
            "intended_owner": policy.get("owner"),
            "context": context,
        },
        request_meta,
    )
    source = _as_dict(source_response.get("source"))

    decision = "allow"
    reason = "policy_allowed"
    allowed_roles = set(policy.get("roles", set()))
    if role not in allowed_roles:
        decision = "deny"
        reason = "role_forbidden"
    elif not required_scopes.issubset(provided_scopes):
        decision = "deny"
        reason = "scope_missing"
    elif policy.get("maker_checker") and actor_id and actor_id in _maker_checker_subjects(context):
        decision = "deny"
        reason = "maker_checker_violation"
    elif policy.get("export_controls_required") and context.get("export_controls_acknowledged") is not True:
        decision = "deny"
        reason = "export_controls_acknowledgement_required"
    elif policy.get("canonical_source_required") and source.get("allowed_as_canonical") is not True:
        decision = "deny"
        reason = "canonical_source_required"
    elif policy.get("adapter_evidence_allowed") and source.get("allowed_as_canonical") is not True and source.get("allowed_as_evidence") is not True:
        decision = "deny"
        reason = "adapter_evidence_or_canonical_source_required"
    elif policy.get("allowed_record_scopes"):
        record_scope = _clean_slug(context.get("record_scope") or payload.get("record_scope"), "", 80)
        if record_scope not in set(policy.get("allowed_record_scopes", set())):
            decision = "deny"
            reason = "record_scope_forbidden"

    if policy.get("connector_transport_only") and decision == "allow":
        reason = "connector_handoff_allowed_liveuin_core_remains_truth"

    decision_id = _clean_id(payload.get("decision_id"), 120) or "access_dec_" + uuid.uuid4().hex[:16]
    stored = store.record_decision(
        {
            "decision_id": decision_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "actor_role": role,
            "surface": _clean_slug(payload.get("surface") or context.get("surface"), "liveuin_core", 100),
            "action": action,
            "resource_type": _clean_slug(resource.get("type") or payload.get("resource_type"), "", 80),
            "resource_id": _clean_id(resource.get("id") or payload.get("resource_id"), 120),
            "decision": decision,
            "reason": reason,
            "required_scopes": sorted(required_scopes),
            "provided_scopes": sorted(provided_scopes),
            "source_family": source.get("source_family", ""),
            "source_truth_status": source.get("truth_status", ""),
            "policy": _policy_summary(policy),
            "context": context,
        },
        request_meta,
    )
    return _envelope(
        "policy_evaluated",
        workspace_id,
        allowed=decision == "allow",
        decision=stored,
        source_assessment=source,
        policy=_policy_summary(policy),
        controls={
            "payment_execution_performed": False,
            "bank_file_created": False,
            "connector_truth_created": False,
            "channel_truth_created": False,
        },
    )


def create_participant_grant(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    workspace_id = _workspace_id(payload.get("workspace_id"))
    case_id = _clean_id(payload.get("case_id"), 120)
    participant_id = _clean_id(payload.get("participant_id") or payload.get("person_id"), 120)
    subject_id = _clean_id(payload.get("subject_id") or participant_id, 120)
    if not case_id:
        return error("case_id_required")
    if not participant_id:
        return error("participant_id_required")

    source_response = classify_source(
        {
            "workspace_id": workspace_id,
            "source_family": payload.get("source_family") or "liveuin_core",
            "source_system": payload.get("source_system") or payload.get("source_family") or "liveuin_core",
            "claim_type": "case",
            "intended_owner": "LiveUIN Core",
            "context": _as_dict(payload.get("context") or payload.get("metadata")),
        },
        request_meta,
    )
    if source_response.get("allowed_as_canonical") is not True:
        return error(
            "canonical_source_required",
            403,
            workspace_id=workspace_id,
            source_assessment=source_response.get("source"),
        )

    consent_state = _clean_slug(payload.get("consent_state"), "consented", 80)

    now = int(time.time())
    grant_id = _clean_id(payload.get("grant_id"), 140)
    if not grant_id:
        grant_id = "pg_" + _hash_payload(
            {
                "workspace_id": workspace_id,
                "case_id": case_id,
                "participant_id": participant_id,
                "grant_type": payload.get("grant_type") or "case_pass_access",
                "created_at": now,
            }
        )[:24]
    raw_status = _clean_slug(payload.get("status"), "active", 80)
    conditions = _g08_g09_conditions(payload, grant_id=grant_id, status=raw_status, consent_state=consent_state, now=now)
    status = _normalize_participant_grant_status(raw_status, consent_state, conditions)
    if status == "pending_evidence":
        conditions = {**conditions, "activation_blocker": _conditions_complete_for_active(conditions)}
    supersedes_grant_id = _clean_id(_as_dict(conditions.get("supersession")).get("supersedes_grant_id"), 140)
    provenance = _redact(
        {
            **_as_dict(payload.get("provenance")),
            "person_id": participant_id,
            "household_case_id": case_id,
            "role_label_non_authoritative": _clean_slug(payload.get("participant_role"), "family", 80),
            "authority_basis": conditions.get("authority_basis", {}),
            "consent_version": conditions.get("consent_version", ""),
            "grant_version": conditions.get("grant_version", ""),
            "issuer": _clean_id(payload.get("issued_by") or payload.get("actor_id"), 120),
        }
    )
    grant = store.upsert_participant_grant(
        {
            "grant_id": grant_id,
            "workspace_id": workspace_id,
            "case_id": case_id,
            "participant_id": participant_id,
            "participant_role": _clean_slug(payload.get("participant_role"), "family", 80),
            "subject_id": subject_id,
            "subject_role": _clean_slug(payload.get("subject_role") or payload.get("participant_role"), "family", 80),
            "grant_type": _clean_slug(payload.get("grant_type"), "case_pass_access", 100),
            "status": status,
            "consent_state": consent_state,
            "allowed_actions": _grant_actions(payload.get("allowed_actions") or payload.get("actions") or ["pass.read"]),
            "allowed_resources": _grant_resources(payload.get("allowed_resources") or payload.get("resources") or ["case", "pass"]),
            "scope": _clean_slug(payload.get("scope"), "case", 80),
            "source_family": _source_family(payload) if payload.get("source_family") else "liveuin_core",
            "issued_by": _clean_id(payload.get("issued_by") or payload.get("actor_id"), 120),
            "conditions": conditions,
            "provenance": provenance,
            "revocation_propagation": {},
            "created_at": now,
            "updated_at": now,
            "expires_at": int(payload.get("expires_at") or 0),
            "revoked_at": 0,
        },
        request_meta,
    )
    if supersedes_grant_id and supersedes_grant_id != grant_id:
        previous = store.get_participant_grant(supersedes_grant_id, workspace_id)
        if previous:
            previous_conditions = _as_dict(previous.get("conditions"))
            previous_supersession = {
                **_as_dict(previous_conditions.get("supersession")),
                "superseded_by_grant_id": grant_id,
                "superseded_at": now,
            }
            store.upsert_participant_grant(
                {
                    **previous,
                    "status": "superseded",
                    "revoked_by": grant.get("issued_by", ""),
                    "revoked_reason": "superseded_by_new_consent_version",
                    "conditions": {**previous_conditions, "supersession": previous_supersession},
                    "revocation_propagation": _revocation_propagation(
                        grant=previous,
                        revoked_by=grant.get("issued_by", ""),
                        reason="superseded_by_new_consent_version",
                        created_at=now,
                    ),
                    "updated_at": now,
                    "revoked_at": now,
                },
                request_meta,
            )
            store.record_participant_grant_event(
                {
                    "event_id": "pge_" + uuid.uuid4().hex[:18],
                    "workspace_id": workspace_id,
                    "grant_id": supersedes_grant_id,
                    "case_id": previous.get("case_id", ""),
                    "participant_id": previous.get("participant_id", ""),
                    "event_type": "participant_grant.superseded",
                    "event_payload": {"superseded_by_grant_id": grant_id, "superseded_at": now},
                    "created_at": now,
                },
                request_meta,
            )
    event = store.record_participant_grant_event(
        {
            "event_id": "pge_" + uuid.uuid4().hex[:18],
            "workspace_id": workspace_id,
            "grant_id": grant.get("grant_id", ""),
            "case_id": case_id,
            "participant_id": participant_id,
            "event_type": "participant_grant.created",
            "event_payload": {
                "status": grant.get("status"),
                "consent_state": grant.get("consent_state"),
                "allowed_actions": grant.get("allowed_actions", []),
                "allowed_resources": grant.get("allowed_resources", []),
                "source_family": grant.get("source_family", ""),
                "purpose": conditions.get("purpose", ""),
                "recipients": conditions.get("recipients", []),
                "visibility_fields": conditions.get("visibility_fields", []),
                "disclosure_model": conditions.get("disclosure_model", ""),
                "consent_version": conditions.get("consent_version", ""),
                "grant_version": conditions.get("grant_version", ""),
                "authority_state": _as_dict(conditions.get("authority_basis")).get("state", ""),
                "supersedes_grant_id": supersedes_grant_id,
            },
            "created_at": now,
        },
        request_meta,
    )
    return _envelope(
        "participant_grant_recorded",
        workspace_id,
        participant_grant=grant,
        event=event,
        controls={
            "durable_grant_required": True,
            "channel_state_non_canonical": True,
            "draft_policy_not_effective": grant.get("status") == "draft_not_effective",
            "participant_authority_required": True,
            "versioned_consent_required": True,
            "role_label_non_authoritative": True,
            "g08_g09_matrix_version": "G08_G09_PARTICIPANT_AUTHORITY_VISIBILITY_CONSENT_MATRIX_v1.0.0",
        },
    )


def evaluate_participant_grant(
    payload: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
    *,
    record_event: bool = True,
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    workspace_id = _workspace_id(payload.get("workspace_id"))
    case_id = _clean_id(payload.get("case_id"), 120)
    participant_id = _clean_id(payload.get("participant_id") or payload.get("person_id"), 120)
    grant_id = _clean_id(payload.get("grant_id"), 140)
    action = _clean_slug(payload.get("action"), "pass.read", 120)
    resource = _as_dict(payload.get("resource"))
    resource_type = _clean_slug(resource.get("type") or payload.get("resource_type"), "", 80)
    resource_id = _clean_id(resource.get("id") or payload.get("resource_id"), 120)
    if not case_id and not grant_id:
        return error("case_id_or_grant_id_required")
    if not participant_id and not grant_id:
        return _grant_denial(
            "participant_grant_missing",
            workspace_id,
            participant_grant={},
            requested={"case_id": case_id, "participant_id": participant_id, "action": action},
        )

    grant = store.get_participant_grant(grant_id, workspace_id) if grant_id else store.find_participant_grant(
        workspace_id=workspace_id,
        case_id=case_id,
        participant_id=participant_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    if not grant:
        return _grant_denial(
            "participant_grant_missing",
            workspace_id,
            participant_grant={},
            requested={"case_id": case_id, "participant_id": participant_id, "action": action},
        )

    now = int(time.time())
    status = _clean_slug(grant.get("status"), "", 80)
    consent_state = _clean_slug(grant.get("consent_state"), "", 80)
    expires_at = int(grant.get("expires_at") or 0)
    allowed_actions = set(str(item) for item in grant.get("allowed_actions") or [])
    allowed_resources = set(str(item) for item in grant.get("allowed_resources") or [])
    resource_keys = {"*", resource_type, resource_id, f"{resource_type}:{resource_id}" if resource_type and resource_id else ""}
    conditions = _as_dict(grant.get("conditions"))
    allowed_visibility_fields = _clean_list(conditions.get("visibility_fields"), slug=True, max_length=120)
    requested_visibility_fields = _clean_list(
        payload.get("visibility_fields") or payload.get("requested_fields") or _as_dict(payload.get("conditions")).get("visibility_fields"),
        slug=True,
        max_length=120,
    )

    reason = "participant_grant_allowed"
    allowed = True
    if participant_id and _clean_id(grant.get("participant_id"), 120) != participant_id:
        allowed = False
        reason = "participant_grant_participant_mismatch"
    elif case_id and _clean_id(grant.get("case_id"), 120) != case_id:
        allowed = False
        reason = "participant_grant_case_mismatch"
    elif status not in ACTIVE_PARTICIPANT_GRANT_STATUSES:
        allowed = False
        reason = "participant_grant_not_active" if status not in DENIED_PARTICIPANT_GRANT_STATUSES else f"participant_grant_{status}"
    elif consent_state in CONSENT_DENIED_STATES:
        allowed = False
        reason = f"participant_consent_{consent_state}" if consent_state else "participant_consent_not_active"
    elif consent_state not in CONSENT_ACTIVE_STATES:
        allowed = False
        reason = "participant_consent_not_active"
    elif expires_at and expires_at <= now:
        allowed = False
        reason = "participant_grant_expired"
    elif action and "*" not in allowed_actions and action not in allowed_actions:
        allowed = False
        reason = "participant_grant_action_forbidden"
    elif (resource_type or resource_id) and not allowed_resources.intersection(resource_keys):
        allowed = False
        reason = "participant_grant_resource_forbidden"
    elif _conditions_complete_for_active(conditions):
        allowed = False
        reason = "participant_grant_" + _conditions_complete_for_active(conditions)
    else:
        mismatch = _requested_condition_mismatches(payload, grant, now)
        if mismatch:
            allowed = False
            reason = mismatch

    event = {}
    if record_event:
        event = store.record_participant_grant_event(
            {
                "event_id": "pge_" + uuid.uuid4().hex[:18],
                "workspace_id": workspace_id,
                "grant_id": grant.get("grant_id", ""),
                "case_id": grant.get("case_id", case_id),
                "participant_id": grant.get("participant_id", participant_id),
                "event_type": "participant_grant.evaluated",
                "event_payload": {
                    "allowed": allowed,
                    "reason": reason,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "purpose": _clean_slug(payload.get("purpose") or _as_dict(payload.get("conditions")).get("purpose"), "", 120),
                    "recipient": _clean_id(payload.get("recipient") or payload.get("recipient_id") or _as_dict(payload.get("conditions")).get("recipient"), 120),
                    "requested_visibility_fields": requested_visibility_fields,
                    "role_label_ignored": bool(payload.get("role") or payload.get("participant_role")),
                },
                "created_at": now,
            },
            request_meta,
        )
    return _envelope(
        "participant_grant_evaluated",
        workspace_id,
        allowed=allowed,
        decision="allow" if allowed else "deny",
        reason=reason,
        participant_grant=grant,
        event=event,
        visibility_fields=allowed_visibility_fields,
        visible_fields=requested_visibility_fields if requested_visibility_fields else allowed_visibility_fields,
        controls={
            "missing_grant_denied": True,
            "role_only_denied": True,
            "share_id_not_a_grant": True,
            "draft_policy_not_effective": status == "draft_not_effective",
            "participant_authority_required": True,
            "versioned_consent_required": True,
            "purpose_matched": allowed,
            "recipient_matched": allowed,
            "visibility_limited": True,
            "disclosure_matched": allowed,
            "audit_event_recorded": bool(event),
            "role_label_non_authoritative": True,
            "g08_g09_matrix_version": "G08_G09_PARTICIPANT_AUTHORITY_VISIBILITY_CONSENT_MATRIX_v1.0.0",
        },
    )


def authorize_participant_grant(
    payload: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
    *,
    record_event: bool = True,
) -> Dict[str, Any]:
    """Fail closed unless the durable participant grant allows this exact use."""
    evaluated = evaluate_participant_grant(payload, request_meta, record_event=record_event)
    if evaluated.get("ok") is False:
        return evaluated
    if evaluated.get("allowed") is True:
        return evaluated
    return error(
        str(evaluated.get("reason") or "participant_grant_required"),
        403,
        workspace_id=str(evaluated.get("workspace_id") or _workspace_id(payload.get("workspace_id"))),
        decision="deny",
        participant_grant=evaluated.get("participant_grant") or {},
        controls=evaluated.get("controls") or {},
    )


def revoke_participant_grant(
    grant_id: str,
    payload: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    workspace_id = _workspace_id(payload.get("workspace_id"))
    grant_key = _clean_id(grant_id or payload.get("grant_id"), 140)
    if not grant_key:
        return error("grant_id_required")
    grant = store.get_participant_grant(grant_key, workspace_id)
    if not grant:
        return error("participant_grant_not_found", 404, workspace_id=workspace_id)
    now = int(time.time())
    revoked_by = _clean_id(payload.get("revoked_by") or payload.get("actor_id"), 120)
    reason = _clean_slug(payload.get("reason"), "owner_revoked", 120)
    target_status = _clean_slug(payload.get("target_status") or payload.get("status"), "revoked", 80)
    if target_status not in {"revoked", "withdrawn", "suspended", "disputed", "expired", "superseded"}:
        target_status = "revoked"
    conditions = _as_dict(grant.get("conditions"))
    if target_status == "withdrawn":
        conditions = {
            **conditions,
            "withdrawal_state": "withdrawn",
            "withdrawal": {
                **_as_dict(conditions.get("withdrawal")),
                "state": "withdrawn",
                "at": now,
                "reason": reason,
            },
        }
    elif target_status == "disputed":
        conditions = {
            **conditions,
            "dispute": {
                **_as_dict(conditions.get("dispute")),
                "state": "disputed",
                "opened_at": now,
                "case_ref": _clean_id(payload.get("dispute_case_ref"), 160),
            },
        }
    propagation = _revocation_propagation(grant=grant, revoked_by=revoked_by, reason=reason, created_at=now)
    revoked = store.upsert_participant_grant(
        {
            **grant,
            "status": target_status,
            "consent_state": "withdrawn" if target_status == "withdrawn" else grant.get("consent_state", ""),
            "revoked_by": revoked_by,
            "revoked_reason": reason,
            "conditions": conditions,
            "revocation_propagation": propagation,
            "updated_at": now,
            "revoked_at": now,
        },
        request_meta,
    )
    event = store.record_participant_grant_event(
        {
            "event_id": "pge_" + uuid.uuid4().hex[:18],
            "workspace_id": workspace_id,
            "grant_id": grant_key,
            "case_id": revoked.get("case_id", ""),
            "participant_id": revoked.get("participant_id", ""),
            "event_type": f"participant_grant.{target_status}",
            "event_payload": {**propagation, "target_status": target_status},
            "created_at": now,
        },
        request_meta,
    )
    return _envelope(
        "participant_grant_revoked",
        workspace_id,
        participant_grant=revoked,
        event=event,
        revocation_propagation=propagation,
        controls={
            "downstream_access_must_fail_closed": True,
            "channel_state_non_canonical": True,
            "browser_state_non_canonical": True,
            "participant_authority_required": True,
            "versioned_consent_required": True,
        },
    )


def _legacy_grant_reconciliation_blocker(grant: Dict[str, Any], now: int) -> str:
    status = _clean_slug(grant.get("status"), "", 80)
    if status not in ACTIVE_PARTICIPANT_GRANT_STATUSES:
        return ""
    consent_state = _clean_slug(grant.get("consent_state"), "", 80)
    if consent_state in CONSENT_DENIED_STATES:
        return f"consent_state_{consent_state}"
    if consent_state not in CONSENT_ACTIVE_STATES:
        return "consent_state_not_active"
    expires_at = int(grant.get("expires_at") or 0)
    if expires_at and expires_at <= now:
        return "grant_expired"
    conditions = _as_dict(grant.get("conditions"))
    blocker = _conditions_complete_for_active(conditions)
    if blocker:
        return blocker
    mismatch = _requested_condition_mismatches({}, grant, now)
    return mismatch


def reconcile_legacy_participant_grants(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    limit: int = 500,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    now = int(time.time())
    candidates: List[Dict[str, Any]] = []
    for status in sorted(ACTIVE_PARTICIPANT_GRANT_STATUSES):
        candidates.extend(
            store.list_participant_grants(
                workspace_id=workspace_id,
                status=status,
                limit=_bounded_limit(limit),
            )
        )
    reconciled: List[Dict[str, Any]] = []
    blockers: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for grant in candidates[: _bounded_limit(limit)]:
        grant_id = _clean_id(grant.get("grant_id"), 140)
        if not grant_id or grant_id in seen:
            continue
        seen.add(grant_id)
        blocker = _legacy_grant_reconciliation_blocker(grant, now)
        if not blocker:
            continue
        original_status = _clean_slug(grant.get("status"), "", 80)
        original_conditions = _as_dict(grant.get("conditions"))
        reconciliation = {
            "version": "ECC-G08-G09-LEGACY-GRANT-RECONCILIATION-v1",
            "status": "pending_evidence",
            "blocker": blocker,
            "reconciled_at": now,
            "original_status": original_status,
            "original_consent_state": _clean_slug(grant.get("consent_state"), "", 80),
            "historical_values_preserved": True,
            "consent_inferred": False,
            "grant_deleted": False,
        }
        conditions = _redact(
            {
                **original_conditions,
                "activation_blocker": blocker,
                "legacy_reconciliation": reconciliation,
            }
        )
        provenance = _redact(
            {
                **_as_dict(grant.get("provenance")),
                "legacy_reconciliation": {
                    "version": reconciliation["version"],
                    "blocker": blocker,
                    "original_status": original_status,
                    "workspace_id": workspace_id,
                },
            }
        )
        event_id = "pge_legacy_reconcile_" + _hash_payload(
            {
                "workspace_id": workspace_id,
                "grant_id": grant_id,
                "version": reconciliation["version"],
                "blocker": blocker,
            }
        )[:18]
        result = store.reconcile_participant_grant_pending_evidence(
            {
                **grant,
                "status": "pending_evidence",
                "conditions": conditions,
                "provenance": provenance,
                "updated_at": now,
            },
            {
                "event_id": event_id,
                "workspace_id": workspace_id,
                "grant_id": grant_id,
                "case_id": grant.get("case_id", ""),
                "participant_id": grant.get("participant_id", ""),
                "event_type": "participant_grant.legacy_reconciled_pending_evidence",
                "event_payload": {
                    **reconciliation,
                    "case_id": grant.get("case_id", ""),
                    "participant_id": grant.get("participant_id", ""),
                },
                "created_at": now,
            },
            request_meta,
        )
        reconciled.append(result)
        blockers.append({"grant_id": grant_id, "blocker": blocker, "original_status": original_status})

    return _envelope(
        "participant_grant_legacy_reconciliation_complete",
        workspace_id,
        reconciliation_version="ECC-G08-G09-LEGACY-GRANT-RECONCILIATION-v1",
        scanned_count=len(seen),
        reconciled_count=len(reconciled),
        reconciled_grants=[item.get("participant_grant", {}) for item in reconciled],
        events=[item.get("event", {}) for item in reconciled],
        blockers=blockers,
        controls={
            "idempotent": True,
            "incomplete_active_limited_grants_pending_evidence": True,
            "historical_values_preserved": True,
            "consent_inferred": False,
            "grant_deleted": False,
            "workspace_isolated": True,
            "g08_g09_matrix_version": "G08_G09_PARTICIPANT_AUTHORITY_VISIBILITY_CONSENT_MATRIX_v1.0.0",
        },
    )


def list_participant_grants(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    case_id: str = "",
    participant_id: str = "",
    status: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    rows = store.list_participant_grants(
        workspace_id=workspace_id,
        case_id=_clean_id(case_id, 120) if case_id else "",
        participant_id=_clean_id(participant_id, 120) if participant_id else "",
        status=_clean_slug(status, "", 80) if status else "",
        limit=_bounded_limit(limit),
    )
    return _envelope("participant_grants_loaded", workspace_id, participant_grants=rows, participant_grant_count=len(rows))


def list_participant_grant_events(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    grant_id: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    rows = store.list_participant_grant_events(
        workspace_id=workspace_id,
        grant_id=_clean_id(grant_id, 140) if grant_id else "",
        limit=_bounded_limit(limit),
    )
    return _envelope("participant_grant_events_loaded", workspace_id, participant_grant_events=rows, event_count=len(rows))


def list_decisions(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    actor_id: str = "",
    action: str = "",
    decision: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    rows = store.list_decisions(
        workspace_id=workspace_id,
        actor_id=_clean_id(actor_id, 96),
        action=_clean_slug(action, "", 120) if action else "",
        decision=_clean_slug(decision, "", 40) if decision else "",
        limit=_bounded_limit(limit),
    )
    return _envelope("decisions_loaded", workspace_id, decisions=rows, decision_count=len(rows))


def list_source_assessments(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    source_family: str = "",
    truth_status: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    rows = store.list_source_assessments(
        workspace_id=workspace_id,
        source_family=_clean_slug(source_family, "", 120) if source_family else "",
        truth_status=_clean_slug(truth_status, "", 80) if truth_status else "",
        limit=_bounded_limit(limit),
    )
    return _envelope("source_assessments_loaded", workspace_id, sources=rows, source_assessment_count=len(rows))


def claim_idempotency(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    workspace_id = _workspace_id(payload.get("workspace_id"))
    key = _clean_id(payload.get("idempotency_key") or payload.get("key"), 160)
    action = _clean_slug(payload.get("action"), "", 120)
    if not key:
        return error("idempotency_key_required")
    if not action:
        return error("action_required")

    actor = _as_dict(payload.get("actor"))
    resource = _as_dict(payload.get("resource"))
    request_payload = _as_dict(payload.get("request_payload") or payload.get("payload") or payload.get("context"))
    response_ref = _as_dict(payload.get("response_ref"))
    request_hash = _hash_payload(request_payload)
    status = "completed" if response_ref else "reserved"
    now = int(time.time())
    try:
        claim_result = store.claim_idempotency_record(
            {
                "claim_id": _clean_id(payload.get("claim_id"), 120) or "access_idem_" + uuid.uuid4().hex[:16],
                "workspace_id": workspace_id,
                "idempotency_key": key,
                "action": action,
                "actor_id": _clean_id(actor.get("actor_id") or payload.get("actor_id"), 96),
                "resource_type": _clean_slug(resource.get("type") or payload.get("resource_type"), "", 80),
                "resource_id": _clean_id(resource.get("id") or payload.get("resource_id"), 120),
                "request_hash": request_hash,
                "status": status,
                "result_status": _clean_slug(payload.get("result_status"), "", 80),
                "request_payload": _redact(request_payload),
                "response_ref": _redact(response_ref),
                "first_seen_at": now,
                "last_seen_at": now,
                "completed_at": now if response_ref else 0,
            },
            request_meta,
        )
    except Exception as exc:
        return error(
            "idempotency_store_unavailable",
            503,
            status="idempotency_unavailable",
            workspace_id=workspace_id,
            duplicate=False,
            conflict=False,
            error_type=exc.__class__.__name__,
        )

    claim = _as_dict(claim_result.get("record"))
    if claim_result.get("created") is not True:
        if claim.get("request_hash") != request_hash:
            return error(
                "idempotency_key_conflict",
                409,
                status="idempotency_conflict",
                workspace_id=workspace_id,
                duplicate=False,
                conflict=True,
                existing_claim=claim,
            )
        try:
            claim = store.touch_idempotency_claim(workspace_id=workspace_id, idempotency_key=key)
        except Exception as exc:
            return error(
                "idempotency_store_unavailable",
                503,
                status="idempotency_unavailable",
                workspace_id=workspace_id,
                duplicate=False,
                conflict=False,
                error_type=exc.__class__.__name__,
            )
        return _envelope(
            "idempotency_duplicate",
            workspace_id,
            duplicate=True,
            conflict=False,
            idempotency=claim,
            controls={
                "mutation_should_reuse_existing_result": True,
                "payment_execution_performed": False,
                "bank_file_created": False,
            },
        )

    return _envelope(
        "idempotency_" + status,
        workspace_id,
        duplicate=False,
        conflict=False,
        idempotency=claim,
        controls={
            "mutation_may_proceed": status == "reserved",
            "mutation_already_completed": status == "completed",
            "payment_execution_performed": False,
            "bank_file_created": False,
        },
    )


def complete_idempotency_claim(
    idempotency_key: str,
    payload: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    workspace_id = _workspace_id(payload.get("workspace_id"))
    key = _clean_id(idempotency_key or payload.get("idempotency_key") or payload.get("key"), 160)
    response_ref = _as_dict(payload.get("response_ref"))
    if not key:
        return error("idempotency_key_required")
    if not response_ref:
        return error("response_ref_required")

    existing = store.get_idempotency_claim(key, workspace_id)
    if not existing:
        return error("idempotency_key_not_found", 404)

    claim = store.update_idempotency_claim(
        workspace_id=workspace_id,
        idempotency_key=key,
        status="completed",
        result_status=_clean_slug(payload.get("result_status"), "completed", 80),
        response_ref=_redact(response_ref),
        completed_at=int(time.time()),
    )
    return _envelope(
        "idempotency_completed",
        workspace_id,
        duplicate=False,
        conflict=False,
        idempotency=claim,
        controls={
            "mutation_already_completed": True,
            "payment_execution_performed": False,
            "bank_file_created": False,
        },
        request_meta_recorded=bool(request_meta),
    )


def list_idempotency_claims(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    action: str = "",
    status: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    rows = store.list_idempotency_claims(
        workspace_id=workspace_id,
        action=_clean_slug(action, "", 120) if action else "",
        status=_clean_slug(status, "", 80) if status else "",
        limit=_bounded_limit(limit),
    )
    return _envelope("idempotency_claims_loaded", workspace_id, idempotency_claims=rows, idempotency_claim_count=len(rows))


def list_adapter_replay_nonces(
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    adapter_id: str = "",
    source_family: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    replay_list = replay_store.list_adapter_replay_nonces if replay_store is not None else store.list_adapter_replay_nonces
    rows = replay_list(
        workspace_id=workspace_id,
        adapter_id=_clean_id(adapter_id, 120) if adapter_id else "",
        source_family=_clean_slug(source_family, "", 120) if source_family else "",
        limit=_bounded_limit(limit),
    )
    return _envelope(
        "adapter_replay_nonces_loaded",
        workspace_id,
        adapter_replay_nonces=rows,
        adapter_replay_nonce_count=len(rows),
    )


def access_status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    workspace_id = _workspace_id(workspace_id)
    stats = store.stats(workspace_id)
    replay_stats = replay_store.stats(workspace_id) if replay_store is not None else {
        "adapter_replay_nonce_count": stats["adapter_replay_nonce_count"],
        "store_driver": "sqlite",
        "shared_replay_store": False,
    }
    return _envelope(
        "core_access_status",
        workspace_id,
        service="liveuin-core-access-governance-preview",
        storage="sqlite",
        sqlite_path=stats["sqlite_path"],
        decision_count=stats["decision_count"],
        source_assessment_count=stats["source_assessment_count"],
        idempotency_claim_count=stats["idempotency_claim_count"],
        adapter_replay_nonce_count=replay_stats["adapter_replay_nonce_count"],
        participant_grant_count=stats.get("participant_grant_count", 0),
        revoked_participant_grant_count=stats.get("revoked_participant_grant_count", 0),
        participant_grant_event_count=stats.get("participant_grant_event_count", 0),
        denied_decision_count=stats["denied_decision_count"],
        replay_store=replay_store.status(workspace_id) if replay_store is not None else {"ok": False, "detail": "replay_store_not_loaded"},
        secret_registry=secret_registry.status() if secret_registry is not None else {"ok": False, "detail": "secret_registry_not_loaded"},
        policy_count=len(POLICIES),
        source_governance={
            "canonical_sources": sorted(CANONICAL_SOURCE_FAMILIES),
            "adapter_evidence_sources": sorted(ADAPTER_EVIDENCE_FAMILIES),
            "display_or_bridge_sources": sorted(DISPLAY_OR_BRIDGE_FAMILIES),
            "claim_owner_count": len(CLAIM_OWNERS),
        },
    )
