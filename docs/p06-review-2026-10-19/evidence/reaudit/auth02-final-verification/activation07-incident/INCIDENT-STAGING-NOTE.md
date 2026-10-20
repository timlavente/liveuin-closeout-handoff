# AUTH02 activation07 incident — staged evidence

Snapshot 2026-10-19T20:17:26.174367+00:00. This append preserves the unsuccessful activation attempt separately from preactivation evidence and earlier immutable packages. It is not a component pass or an issue freeze.

The safe activation result started at 2026-10-19 20:14:35.895325 UTC (20 October 04:14:35 Singapore). Its entry, candidate and fallback guarded prestart probes all passed. The post-restart process check raised process_argv_drift. The controller installed the previously reviewed closed fallback, attempted its guarded recovery, encountered the same process check, and stopped the service. Final controller status: service_stopped_for_closed_recovery.

Root reports the current process PID is zero and the target source is the closed fallback aee0ce11a4ffe48242b18de4a67463409765d80f43f15a68c6d40facc6e143. Configuration equality and prechange backup had passed before mutation. These current-state and backup statements are root-reported operational observations; the copied safe JSON itself proves the controller result and probe statuses.

Unlike the earlier preactivation staging snapshot, this attempt did replace the one AUTH02 Identity API target and restart its service, then install the closed fallback and stop it. No original unguarded source was restored. The safe result records no accounts created, no emails requested, no flags changed, no database restore and no public access opened. No payment transaction, customer-case work, family row or later frozen row was started.

The root and source reviewers are checking the bounded Type=simple startup-wrapper timing explanation. That explanation remains an engineering diagnosis until the corrected runtime check and actual recovery succeed. This record does not label the live component healthy or the owner proof complete. Owner sign-in, deployed denial checks and final payment-lock evidence remain to be established after recovery.

Package07 is immutable. Its hashes, 44-file source manifest, controller, prestart probe, staging helper and target manifests are retained here; its archive and root-private configuration/probe outputs are excluded. The previous post-RETENTION04 staging remains byte-for-byte unchanged and describes its own earlier point in time. A later recovery result must append to this incident history, not replace it.

Ecosystem boundary checked: this incident is confined to the existing LiveUIN Core/Identity service and one API target. It authorizes no sibling-site, imported-tenancy, payment or public-access change. Parent working documents and previous durable retention remain untouched by this reviewer.
