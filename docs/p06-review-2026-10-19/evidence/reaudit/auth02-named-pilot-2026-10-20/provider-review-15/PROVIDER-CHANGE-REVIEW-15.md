# Provider change review15

The fresh deployed provider hash is `a2034f5d0990719d39cbf378c92a87e7b72011b31a99483ccb75cecab06ba2dc`. Its only semantic change from reviewed5945fd77 is the SetupIntent form key `payment_method_types[]` becoming `allowed_payment_method_types[]` at line84. Normalizing that one AST constant makes the entire source AST identical to the prior version. The diff and machine-readable result are retained alongside this note.

This delta does not weaken the existing payment lock. The provider still rejects any key without `sk_test_`, uses the same fixed Stripe origin and endpoint methods, rejects redirects, and adds no charge or PaymentIntent operation. The unchanged service still requires provider objects with `livemode: false` and SetupIntent responses with exactly `["card"]` payment methods. Fresh server hashes confirm service `def3ce37…` and API `cb04159…` are unchanged. Ops was active at PID3724514 with no pending daemon reload.

Root separately reported current runtime classification: the four reviewed live rails remain absent/false, Core's Stripe credential is test, the old adapter remains a non-dispatching reference, and customer-card sandbox is enabled. This reviewer did not read credentials or repeat that protected runtime classification. The source change is compatible with preserving that bounded lock evidence. Any updated classifier pin must explicitly reference this new reviewed source; the old pin must not be called a match.

This review does not prove Endive compatibility, a card setup, a payment or a refund. No provider API, customer record, credential value or production mutation was used.

Boundary check: this remains LiveUIN Core's test-only card adapter. It does not move payment truth to a sibling product or place rent/deposits into platform custody. No imported tenancy was used or contacted.
