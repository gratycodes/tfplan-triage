<!-- tfplan-triage:default -->
### Terraform plan triage

**6 critical, 1 high, 1 medium** · 11 changes (+4 ~3 -/+2 -2)

| Severity | What happens | Resource |
|---|---|---|
| **critical** | Replaces disk (forced by `type`): the volume contents | `google_compute_disk.cache` |
| **critical** | Deletes key: the key material; anything encrypted with it becomes unreadable | `google_kms_crypto_key.card_vault` |
| **critical** | Replaces database (forced by `region`): all data and automated backups | `google_sql_database_instance.ledger` |
| **critical** | Deletes bucket: all objects | `google_storage_bucket.exports` |
| **critical** | Grants access: `roles/storage.objectViewer` granted to `allUsers` (public) via google_storage_bucket_iam_member | `google_storage_bucket_iam_member.reports_partner` |
| **critical** | Exposes: port 22 (SSH) open to the internet (from `0.0.0.0/0`) | `google_compute_firewall.ssh_iap_debug` |
| **high** | Grants access: `roles/owner` granted to `serviceAccount:ci-deployer@acme-payments-prod.iam.gserviceaccount.com` | `google_project_iam_member.ci_owner` |
| medium | Exposes: reserves an external IP address | `google_compute_address.partner_sftp` |

<details><summary>Why these were flagged</summary>

**`google_compute_disk.cache`** (critical, destroy-stateful)
- Replaces disk (forced by `type`): the volume contents
- `type`: "pd-standard" → "pd-ssd"
- The old object is destroyed before the new one exists.
- `lifecycle { prevent_destroy = true }` is not set in the source.

**`google_kms_crypto_key.card_vault`** (critical, destroy-stateful)
- Deletes key: the key material; anything encrypted with it becomes unreadable
- The resource block was removed from the configuration.

**`google_sql_database_instance.ledger`** (critical, destroy-stateful)
- Replaces database (forced by `region`): all data and automated backups
- `region`: "europe-west1" → "europe-west2"
- The old object is destroyed before the new one exists.
- `deletion_protection` is on in the current state. This change also turns it off, but the delete uses the current setting, so expect this apply to fail at the delete step; the next apply after it would go through.
- `lifecycle { prevent_destroy = true }` is not set in the source.

**`google_storage_bucket.exports`** (critical, destroy-stateful)
- Deletes bucket: all objects
- The resource block was removed from the configuration.
- `force_destroy = true`: the provider deletes the contents too, without asking.

**`google_storage_bucket_iam_member.reports_partner`** (critical, iam-widening)
- Grants access: `roles/storage.objectViewer` granted to `allUsers` (public) via google_storage_bucket_iam_member

**`google_compute_firewall.ssh_iap_debug`** (critical, network-exposure)
- Exposes: port 22 (SSH) open to the internet (from `0.0.0.0/0`)

**`google_project_iam_member.ci_owner`** (high, iam-widening)
- Grants access: `roles/owner` granted to `serviceAccount:ci-deployer@acme-payments-prod.iam.gserviceaccount.com`

**`google_compute_address.partner_sftp`** (medium, network-exposure)
- Exposes: reserves an external IP address

</details>

<details><summary>3 lower-risk changes</summary>

**Updates to labels only** (3)
`google_pubsub_topic.events["chargebacks"]`, `google_pubsub_topic.events["refunds"]`, `google_pubsub_topic.events["settlements"]`

</details>

<sub>tfplan-triage · plan from Terraform/OpenTofu 1.13.1 · rule-based, not a substitute for reading the plan</sub>
