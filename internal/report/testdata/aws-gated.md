<!-- tfplan-triage:default -->
### Terraform plan triage

**6 critical, 2 high, 1 medium** · 16 changes (+4 ~7 -/+3 -2)

> [!CAUTION]
> **Check failed:** 4 findings at `high` or above need approval. After review, add `approved-security` to the PR.

| Severity | What happens | Resource |
|---|---|---|
| **critical** | Deletes bucket: all objects | `aws_s3_bucket.scratch` |
| **critical** | Replaces bucket (forced by `bucket`): all objects | `aws_s3_bucket.statements` |
| **critical** | Replaces database (forced by `storage_encrypted`): all data and automated backups | `module.ledger_db.aws_db_instance.this` |
| **critical** | Deletes key: the key material; anything encrypted with it becomes unreadable | `module.ledger_db.aws_kms_key.legacy` |
| **critical**, blocking | Grants access: attaches AWS managed `AdministratorAccess` | `aws_iam_role_policy_attachment.ci_admin` |
| **critical**, blocking | Exposes: port 22 (SSH) open to the internet (from `0.0.0.0/0`) | `aws_vpc_security_group_ingress_rule.ssh_debug` |
| **high**, blocking | Widens access: can grant itself more access (`iam:PassRole` on `*`) (+1 more) | `aws_iam_role_policy.ci_deployer` |
| **high**, blocking | Exposes: S3 Block Public Access `block_public_policy = false` (+1 more) | `aws_s3_bucket_public_access_block.statements` |
| medium | Exposes: port 443 open to the internet (from `0.0.0.0/0`) | `aws_vpc_security_group_ingress_rule.https_public` |

<details><summary>Why these were flagged</summary>

**`aws_s3_bucket.scratch`** (critical, destroy-stateful, approved by `approved-destroy`)
- Deletes bucket: all objects
- The resource block was removed from the configuration.
- `force_destroy = true`: the provider deletes the contents too, without asking.

**`aws_s3_bucket.statements`** (critical, destroy-stateful, approved by `approved-destroy`)
- Replaces bucket (forced by `bucket`): all objects
- `bucket`: "acme-statements-prod" → "acme-statements-prod-eu"
- The old object is destroyed before the new one exists.

**`module.ledger_db.aws_db_instance.this`** (critical, destroy-stateful, approved by `approved-destroy`)
- Replaces database (forced by `storage_encrypted`): all data and automated backups
- `storage_encrypted`: false → true
- The old object is destroyed before the new one exists.
- `deletion_protection` is off, so the provider will not stop it.

**`module.ledger_db.aws_kms_key.legacy`** (critical, destroy-stateful, approved by `approved-destroy`)
- Deletes key: the key material; anything encrypted with it becomes unreadable
- The resource block was removed from the configuration.

**`aws_iam_role_policy_attachment.ci_admin`** (critical, iam-widening, needs `approved-security`)
- Grants access: attaches AWS managed `AdministratorAccess`

**`aws_vpc_security_group_ingress_rule.ssh_debug`** (critical, network-exposure, needs `approved-security`)
- Exposes: port 22 (SSH) open to the internet (from `0.0.0.0/0`)

**`aws_iam_role_policy.ci_deployer`** (high, iam-widening, needs `approved-security`)
- Widens access: can grant itself more access (`iam:PassRole` on `*`) (+1 more)
- every s3 action on every resource (`s3:*` on `*`)

**`aws_s3_bucket_public_access_block.statements`** (high, network-exposure, needs `approved-security`)
- Exposes: S3 Block Public Access `block_public_policy = false` (+1 more)
- S3 Block Public Access `restrict_public_buckets = false`

**`aws_vpc_security_group_ingress_rule.https_public`** (medium, network-exposure)
- Exposes: port 443 open to the internet (from `0.0.0.0/0`)

</details>

<details><summary>By module</summary>

| Module | + | ~ | -/+ | - | Findings | Highest |
|---|--:|--:|--:|--:|--:|---|
| `(root)` | 4 | 7 | 2 | 1 | 8 | critical |
| `module.ledger_db` | 0 | 0 | 1 | 1 | 2 | critical |

</details>

<details><summary>8 lower-risk changes</summary>

**Low / info**
- `aws_s3_bucket_public_access_block.statements`: Replaces aws_s3_bucket_public_access_block (forced by `bucket`)

**Updates to tags only** (6)
`aws_cloudwatch_log_group.service["api"]`, `aws_cloudwatch_log_group.service["ledger"]`, `aws_cloudwatch_log_group.service["payouts"]`, `aws_cloudwatch_log_group.service["refunds"]`, `aws_cloudwatch_log_group.service["webhooks"]`, `aws_cloudwatch_log_group.service["worker"]`

**Other changes** (1)
- create `aws_sqs_queue.refund_events`

</details>

<sub>tfplan-triage · plan from Terraform/OpenTofu 1.16.5 · rule-based, not a substitute for reading the plan</sub>
