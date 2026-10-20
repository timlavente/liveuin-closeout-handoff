import { Route as Route_root } from "./routes/__root";
import { Route as Route_account_language } from "./routes/account.language";
import { Route as Route_account_notifications } from "./routes/account.notifications";
import { Route as Route_account_privacy } from "./routes/account.privacy";
import { Route as Route_account_profile } from "./routes/account.profile";
import { Route as Route_account_security } from "./routes/account.security";
import { Route as Route_account_settings } from "./routes/account.settings";
import { Route as Route_auth_cancel_deletion } from "./routes/auth.cancel-deletion";
import { Route as Route_auth_complete_profile } from "./routes/auth.complete-profile";
import { Route as Route_auth_continue_tenant } from "./routes/auth.continue-tenant";
import { Route as Route_auth_forgot_password } from "./routes/auth.forgot-password";
import { Route as Route_auth_sign_in } from "./routes/auth.sign-in";
import { Route as Route_auth_sign_up } from "./routes/auth.sign-up";
import { Route as Route_family_home } from "./routes/family.home";
import { Route as Route_index } from "./routes/index";
import { Route as Route_journey } from "./routes/journey";
import { Route as Route_landlord_home } from "./routes/landlord.home";
import { Route as Route_localpro_account } from "./routes/localpro.account";
import { Route as Route_localpro_availability } from "./routes/localpro.availability";
import { Route as Route_localpro_compliance } from "./routes/localpro.compliance";
import { Route as Route_localpro_earnings__payoutId } from "./routes/localpro.earnings.$payoutId";
import { Route as Route_localpro_earnings_settlement__settlementId } from "./routes/localpro.earnings.settlement.$settlementId";
import { Route as Route_localpro_earnings } from "./routes/localpro.earnings";
import { Route as Route_localpro_eligibility } from "./routes/localpro.eligibility";
import { Route as Route_localpro_history__jobId } from "./routes/localpro.history.$jobId";
import { Route as Route_localpro_history } from "./routes/localpro.history";
import { Route as Route_localpro_home } from "./routes/localpro.home";
import { Route as Route_localpro_jobs__jobId_accepted } from "./routes/localpro.jobs.$jobId.accepted";
import { Route as Route_localpro_jobs__jobId_active } from "./routes/localpro.jobs.$jobId.active";
import { Route as Route_localpro_jobs__jobId_address } from "./routes/localpro.jobs.$jobId.address";
import { Route as Route_localpro_jobs__jobId_incident } from "./routes/localpro.jobs.$jobId.incident";
import { Route as Route_localpro_jobs__jobId_proof_approved } from "./routes/localpro.jobs.$jobId.proof.approved";
import { Route as Route_localpro_jobs__jobId_proof_pending } from "./routes/localpro.jobs.$jobId.proof.pending";
import { Route as Route_localpro_jobs__jobId_proof_rejected } from "./routes/localpro.jobs.$jobId.proof.rejected";
import { Route as Route_localpro_jobs__jobId_proof } from "./routes/localpro.jobs.$jobId.proof";
import { Route as Route_localpro_jobs__jobId } from "./routes/localpro.jobs.$jobId";
import { Route as Route_localpro_jobs } from "./routes/localpro.jobs";
import { Route as Route_localpro_payouts_history } from "./routes/localpro.payouts.history";
import { Route as Route_localpro_payouts_method } from "./routes/localpro.payouts.method";
import { Route as Route_localpro_verification } from "./routes/localpro.verification";
import { Route as Route_messages__threadId } from "./routes/messages.$threadId";
import { Route as Route_messages } from "./routes/messages";
import { Route as Route_offline } from "./routes/offline";
import { Route as Route_operator_home } from "./routes/operator.home";
import { Route as Route_partner_home } from "./routes/partner.home";
import { Route as Route_states } from "./routes/states";
import { Route as Route_tenant_account } from "./routes/tenant.account";
import { Route as Route_tenant_address_reveal } from "./routes/tenant.address-reveal";
import { Route as Route_tenant_agreement_pending } from "./routes/tenant.agreement.pending";
import { Route as Route_tenant_agreement } from "./routes/tenant.agreement";
import { Route as Route_tenant_alerts } from "./routes/tenant.alerts";
import { Route as Route_tenant_applications__appId } from "./routes/tenant.applications.$appId";
import { Route as Route_tenant_applications_new } from "./routes/tenant.applications.new";
import { Route as Route_tenant_bookings__bookingId } from "./routes/tenant.bookings.$bookingId";
import { Route as Route_tenant_compare } from "./routes/tenant.compare";
import { Route as Route_tenant_documents__docId } from "./routes/tenant.documents.$docId";
import { Route as Route_tenant_documents } from "./routes/tenant.documents";
import { Route as Route_tenant_explore } from "./routes/tenant.explore";
import { Route as Route_tenant_family_revoke } from "./routes/tenant.family.revoke";
import { Route as Route_tenant_family } from "./routes/tenant.family";
import { Route as Route_tenant_first72 } from "./routes/tenant.first72";
import { Route as Route_tenant_handover } from "./routes/tenant.handover";
import { Route as Route_tenant_home } from "./routes/tenant.home";
import { Route as Route_tenant_listings__listingId } from "./routes/tenant.listings.$listingId";
import { Route as Route_tenant_locker } from "./routes/tenant.locker";
import { Route as Route_tenant_marketplace__offerId } from "./routes/tenant.marketplace.$offerId";
import { Route as Route_tenant_marketplace_book__serviceId } from "./routes/tenant.marketplace.book.$serviceId";
import { Route as Route_tenant_marketplace_bundle__bundleId } from "./routes/tenant.marketplace.bundle.$bundleId";
import { Route as Route_tenant_marketplace_dispute } from "./routes/tenant.marketplace.dispute";
import { Route as Route_tenant_marketplace_order__orderId } from "./routes/tenant.marketplace.order.$orderId";
import { Route as Route_tenant_marketplace_provider__providerId } from "./routes/tenant.marketplace.provider.$providerId";
import { Route as Route_tenant_marketplace_rewards } from "./routes/tenant.marketplace.rewards";
import { Route as Route_tenant_marketplace_service__serviceId } from "./routes/tenant.marketplace.service.$serviceId";
import { Route as Route_tenant_marketplace_terms } from "./routes/tenant.marketplace.terms";
import { Route as Route_tenant_marketplace } from "./routes/tenant.marketplace";
import { Route as Route_tenant_movein } from "./routes/tenant.movein";
import { Route as Route_tenant_notifications__notifId } from "./routes/tenant.notifications.$notifId";
import { Route as Route_tenant_notifications } from "./routes/tenant.notifications";
import { Route as Route_tenant_pass_share } from "./routes/tenant.pass.share";
import { Route as Route_tenant_payments_autopay } from "./routes/tenant.payments.autopay";
import { Route as Route_tenant_payments_bill__billId } from "./routes/tenant.payments.bill.$billId";
import { Route as Route_tenant_payments_failed } from "./routes/tenant.payments.failed";
import { Route as Route_tenant_payments_methods } from "./routes/tenant.payments.methods";
import { Route as Route_tenant_payments_receipt__receiptId } from "./routes/tenant.payments.receipt.$receiptId";
import { Route as Route_tenant_payments_receipts } from "./routes/tenant.payments.receipts";
import { Route as Route_tenant_payments_refund } from "./routes/tenant.payments.refund";
import { Route as Route_tenant_payments_success } from "./routes/tenant.payments.success";
import { Route as Route_tenant_payments } from "./routes/tenant.payments";
import { Route as Route_tenant_saved } from "./routes/tenant.saved";
import { Route as Route_tenant_search_filters } from "./routes/tenant.search.filters";
import { Route as Route_tenant_search } from "./routes/tenant.search";
import { Route as Route_tenant_support__ticketId } from "./routes/tenant.support.$ticketId";
import { Route as Route_tenant_support_dispute } from "./routes/tenant.support.dispute";
import { Route as Route_tenant_support_history } from "./routes/tenant.support.history";
import { Route as Route_tenant_support_new } from "./routes/tenant.support.new";
import { Route as Route_tenant_support } from "./routes/tenant.support";
import { Route as Route_tenant_utilities__chargeId } from "./routes/tenant.utilities.$chargeId";
import { Route as Route_tenant_utilities_dispute } from "./routes/tenant.utilities.dispute";
import { Route as Route_tenant_utilities } from "./routes/tenant.utilities";
import { Route as Route_tenant_viewings_request } from "./routes/tenant.viewings.request";
import { Route as Route_tenant_viewings } from "./routes/tenant.viewings";
import { Route as Route_welcome } from "./routes/welcome";

export const nativeLovableRouteParity = [
  { path: "/", component: Route_root.options.component, source: "__root", active: false, mapping: "native-shell-root" },
  { path: "/account/language", component: Route_account_language.options.component, source: "account.language", active: true, mapping: "native-route" },
  { path: "/account/notifications", component: Route_account_notifications.options.component, source: "account.notifications", active: true, mapping: "native-route" },
  { path: "/account/privacy", component: Route_account_privacy.options.component, source: "account.privacy", active: true, mapping: "native-route" },
  { path: "/account/profile", component: Route_account_profile.options.component, source: "account.profile", active: true, mapping: "native-route" },
  { path: "/account/security", component: Route_account_security.options.component, source: "account.security", active: true, mapping: "native-route" },
  { path: "/account/settings", component: Route_account_settings.options.component, source: "account.settings", active: true, mapping: "native-route" },
  { path: "/auth/cancel-deletion", component: Route_auth_cancel_deletion.options.component, source: "auth.cancel-deletion", active: true, mapping: "native-route" },
  { path: "/auth/complete-profile", component: Route_auth_complete_profile.options.component, source: "auth.complete-profile", active: true, mapping: "native-route" },
  { path: "/auth/continue-tenant", component: Route_auth_continue_tenant.options.component, source: "auth.continue-tenant", active: true, mapping: "native-route" },
  { path: "/auth/forgot-password", component: Route_auth_forgot_password.options.component, source: "auth.forgot-password", active: true, mapping: "native-route" },
  { path: "/auth/sign-in", component: Route_auth_sign_in.options.component, source: "auth.sign-in", active: true, mapping: "native-route" },
  { path: "/auth/sign-up", component: Route_auth_sign_up.options.component, source: "auth.sign-up", active: true, mapping: "native-route" },
  { path: "/family/home", component: Route_family_home.options.component, source: "family.home", active: true, mapping: "native-route" },
  { path: "/", component: Route_index.options.component, source: "index", active: false, mapping: "native-root-redirect" },
  { path: "/journey", component: Route_journey.options.component, source: "journey", active: true, mapping: "native-route" },
  { path: "/landlord/home", component: Route_landlord_home.options.component, source: "landlord.home", active: true, mapping: "native-route" },
  { path: "/localpro/account", component: Route_localpro_account.options.component, source: "localpro.account", active: true, mapping: "native-route" },
  { path: "/localpro/availability", component: Route_localpro_availability.options.component, source: "localpro.availability", active: true, mapping: "native-route" },
  { path: "/localpro/compliance", component: Route_localpro_compliance.options.component, source: "localpro.compliance", active: true, mapping: "native-route" },
  { path: "/localpro/earnings/:payoutId", component: Route_localpro_earnings__payoutId.options.component, source: "localpro.earnings.$payoutId", active: true, mapping: "native-route" },
  { path: "/localpro/earnings/settlement/:settlementId", component: Route_localpro_earnings_settlement__settlementId.options.component, source: "localpro.earnings.settlement.$settlementId", active: true, mapping: "native-route" },
  { path: "/localpro/earnings", component: Route_localpro_earnings.options.component, source: "localpro.earnings", active: true, mapping: "native-route" },
  { path: "/localpro/eligibility", component: Route_localpro_eligibility.options.component, source: "localpro.eligibility", active: true, mapping: "native-route" },
  { path: "/localpro/history/:jobId", component: Route_localpro_history__jobId.options.component, source: "localpro.history.$jobId", active: true, mapping: "native-route" },
  { path: "/localpro/history", component: Route_localpro_history.options.component, source: "localpro.history", active: true, mapping: "native-route" },
  { path: "/localpro/home", component: Route_localpro_home.options.component, source: "localpro.home", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/accepted", component: Route_localpro_jobs__jobId_accepted.options.component, source: "localpro.jobs.$jobId.accepted", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/active", component: Route_localpro_jobs__jobId_active.options.component, source: "localpro.jobs.$jobId.active", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/address", component: Route_localpro_jobs__jobId_address.options.component, source: "localpro.jobs.$jobId.address", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/incident", component: Route_localpro_jobs__jobId_incident.options.component, source: "localpro.jobs.$jobId.incident", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/proof/approved", component: Route_localpro_jobs__jobId_proof_approved.options.component, source: "localpro.jobs.$jobId.proof.approved", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/proof/pending", component: Route_localpro_jobs__jobId_proof_pending.options.component, source: "localpro.jobs.$jobId.proof.pending", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/proof/rejected", component: Route_localpro_jobs__jobId_proof_rejected.options.component, source: "localpro.jobs.$jobId.proof.rejected", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId/proof", component: Route_localpro_jobs__jobId_proof.options.component, source: "localpro.jobs.$jobId.proof", active: true, mapping: "native-route" },
  { path: "/localpro/jobs/:jobId", component: Route_localpro_jobs__jobId.options.component, source: "localpro.jobs.$jobId", active: true, mapping: "native-route" },
  { path: "/localpro/jobs", component: Route_localpro_jobs.options.component, source: "localpro.jobs", active: true, mapping: "native-route" },
  { path: "/localpro/payouts/history", component: Route_localpro_payouts_history.options.component, source: "localpro.payouts.history", active: true, mapping: "native-route" },
  { path: "/localpro/payouts/method", component: Route_localpro_payouts_method.options.component, source: "localpro.payouts.method", active: true, mapping: "native-route" },
  { path: "/localpro/verification", component: Route_localpro_verification.options.component, source: "localpro.verification", active: true, mapping: "native-route" },
  { path: "/messages/:threadId", component: Route_messages__threadId.options.component, source: "messages.$threadId", active: true, mapping: "native-route" },
  { path: "/messages", component: Route_messages.options.component, source: "messages", active: true, mapping: "native-route" },
  { path: "/offline", component: Route_offline.options.component, source: "offline", active: true, mapping: "native-route" },
  { path: "/operator/home", component: Route_operator_home.options.component, source: "operator.home", active: true, mapping: "native-route" },
  { path: "/partner/home", component: Route_partner_home.options.component, source: "partner.home", active: true, mapping: "native-route" },
  { path: "/states", component: Route_states.options.component, source: "states", active: true, mapping: "native-route" },
  { path: "/tenant/account", component: Route_tenant_account.options.component, source: "tenant.account", active: true, mapping: "native-route" },
  { path: "/tenant/address-reveal", component: Route_tenant_address_reveal.options.component, source: "tenant.address-reveal", active: true, mapping: "native-route" },
  { path: "/tenant/agreement/pending", component: Route_tenant_agreement_pending.options.component, source: "tenant.agreement.pending", active: true, mapping: "native-route" },
  { path: "/tenant/agreement", component: Route_tenant_agreement.options.component, source: "tenant.agreement", active: true, mapping: "native-route" },
  { path: "/tenant/alerts", component: Route_tenant_alerts.options.component, source: "tenant.alerts", active: true, mapping: "native-route" },
  { path: "/tenant/applications/:appId", component: Route_tenant_applications__appId.options.component, source: "tenant.applications.$appId", active: true, mapping: "native-route" },
  { path: "/tenant/applications/new", component: Route_tenant_applications_new.options.component, source: "tenant.applications.new", active: true, mapping: "native-route" },
  { path: "/tenant/bookings/:bookingId", component: Route_tenant_bookings__bookingId.options.component, source: "tenant.bookings.$bookingId", active: true, mapping: "native-route" },
  { path: "/tenant/compare", component: Route_tenant_compare.options.component, source: "tenant.compare", active: true, mapping: "native-route" },
  { path: "/tenant/documents/:docId", component: Route_tenant_documents__docId.options.component, source: "tenant.documents.$docId", active: true, mapping: "native-route" },
  { path: "/tenant/documents", component: Route_tenant_documents.options.component, source: "tenant.documents", active: true, mapping: "native-route" },
  { path: "/tenant/explore", component: Route_tenant_explore.options.component, source: "tenant.explore", active: true, mapping: "native-route" },
  { path: "/tenant/family/revoke", component: Route_tenant_family_revoke.options.component, source: "tenant.family.revoke", active: true, mapping: "native-route" },
  { path: "/tenant/family", component: Route_tenant_family.options.component, source: "tenant.family", active: true, mapping: "native-route" },
  { path: "/tenant/first72", component: Route_tenant_first72.options.component, source: "tenant.first72", active: true, mapping: "native-route" },
  { path: "/tenant/handover", component: Route_tenant_handover.options.component, source: "tenant.handover", active: true, mapping: "native-route" },
  { path: "/tenant/home", component: Route_tenant_home.options.component, source: "tenant.home", active: true, mapping: "native-route" },
  { path: "/tenant/listings/:listingId", component: Route_tenant_listings__listingId.options.component, source: "tenant.listings.$listingId", active: true, mapping: "native-route" },
  { path: "/tenant/locker", component: Route_tenant_locker.options.component, source: "tenant.locker", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/:offerId", component: Route_tenant_marketplace__offerId.options.component, source: "tenant.marketplace.$offerId", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/book/:serviceId", component: Route_tenant_marketplace_book__serviceId.options.component, source: "tenant.marketplace.book.$serviceId", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/bundle/:bundleId", component: Route_tenant_marketplace_bundle__bundleId.options.component, source: "tenant.marketplace.bundle.$bundleId", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/dispute", component: Route_tenant_marketplace_dispute.options.component, source: "tenant.marketplace.dispute", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/order/:orderId", component: Route_tenant_marketplace_order__orderId.options.component, source: "tenant.marketplace.order.$orderId", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/provider/:providerId", component: Route_tenant_marketplace_provider__providerId.options.component, source: "tenant.marketplace.provider.$providerId", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/rewards", component: Route_tenant_marketplace_rewards.options.component, source: "tenant.marketplace.rewards", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/service/:serviceId", component: Route_tenant_marketplace_service__serviceId.options.component, source: "tenant.marketplace.service.$serviceId", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace/terms", component: Route_tenant_marketplace_terms.options.component, source: "tenant.marketplace.terms", active: true, mapping: "native-route" },
  { path: "/tenant/marketplace", component: Route_tenant_marketplace.options.component, source: "tenant.marketplace", active: true, mapping: "native-route" },
  { path: "/tenant/movein", component: Route_tenant_movein.options.component, source: "tenant.movein", active: true, mapping: "native-route" },
  { path: "/tenant/notifications/:notifId", component: Route_tenant_notifications__notifId.options.component, source: "tenant.notifications.$notifId", active: true, mapping: "native-route" },
  { path: "/tenant/notifications", component: Route_tenant_notifications.options.component, source: "tenant.notifications", active: true, mapping: "native-route" },
  { path: "/tenant/pass/share", component: Route_tenant_pass_share.options.component, source: "tenant.pass.share", active: true, mapping: "native-route" },
  { path: "/tenant/payments/autopay", component: Route_tenant_payments_autopay.options.component, source: "tenant.payments.autopay", active: true, mapping: "native-route" },
  { path: "/tenant/payments/bill/:billId", component: Route_tenant_payments_bill__billId.options.component, source: "tenant.payments.bill.$billId", active: true, mapping: "native-route" },
  { path: "/tenant/payments/failed", component: Route_tenant_payments_failed.options.component, source: "tenant.payments.failed", active: true, mapping: "native-route" },
  { path: "/tenant/payments/methods", component: Route_tenant_payments_methods.options.component, source: "tenant.payments.methods", active: true, mapping: "native-route" },
  { path: "/tenant/payments/receipt/:receiptId", component: Route_tenant_payments_receipt__receiptId.options.component, source: "tenant.payments.receipt.$receiptId", active: true, mapping: "native-route" },
  { path: "/tenant/payments/receipts", component: Route_tenant_payments_receipts.options.component, source: "tenant.payments.receipts", active: true, mapping: "native-route" },
  { path: "/tenant/payments/refund", component: Route_tenant_payments_refund.options.component, source: "tenant.payments.refund", active: true, mapping: "native-route" },
  { path: "/tenant/payments/success", component: Route_tenant_payments_success.options.component, source: "tenant.payments.success", active: true, mapping: "native-route" },
  { path: "/tenant/payments", component: Route_tenant_payments.options.component, source: "tenant.payments", active: true, mapping: "native-route" },
  { path: "/tenant/saved", component: Route_tenant_saved.options.component, source: "tenant.saved", active: true, mapping: "native-route" },
  { path: "/tenant/search/filters", component: Route_tenant_search_filters.options.component, source: "tenant.search.filters", active: true, mapping: "native-route" },
  { path: "/tenant/search", component: Route_tenant_search.options.component, source: "tenant.search", active: true, mapping: "native-route" },
  { path: "/tenant/support/:ticketId", component: Route_tenant_support__ticketId.options.component, source: "tenant.support.$ticketId", active: true, mapping: "native-route" },
  { path: "/tenant/support/dispute", component: Route_tenant_support_dispute.options.component, source: "tenant.support.dispute", active: true, mapping: "native-route" },
  { path: "/tenant/support/history", component: Route_tenant_support_history.options.component, source: "tenant.support.history", active: true, mapping: "native-route" },
  { path: "/tenant/support/new", component: Route_tenant_support_new.options.component, source: "tenant.support.new", active: true, mapping: "native-route" },
  { path: "/tenant/support", component: Route_tenant_support.options.component, source: "tenant.support", active: true, mapping: "native-route" },
  { path: "/tenant/utilities/:chargeId", component: Route_tenant_utilities__chargeId.options.component, source: "tenant.utilities.$chargeId", active: true, mapping: "native-route" },
  { path: "/tenant/utilities/dispute", component: Route_tenant_utilities_dispute.options.component, source: "tenant.utilities.dispute", active: true, mapping: "native-route" },
  { path: "/tenant/utilities", component: Route_tenant_utilities.options.component, source: "tenant.utilities", active: true, mapping: "native-route" },
  { path: "/tenant/viewings/request", component: Route_tenant_viewings_request.options.component, source: "tenant.viewings.request", active: true, mapping: "native-route" },
  { path: "/tenant/viewings", component: Route_tenant_viewings.options.component, source: "tenant.viewings", active: true, mapping: "native-route" },
  { path: "/welcome", component: Route_welcome.options.component, source: "welcome", active: true, mapping: "native-route" },
].filter((route) => Boolean(route.component) || !route.active);

export const nativeLovableRoutes = nativeLovableRouteParity.filter((route) => route.active && Boolean(route.component));
