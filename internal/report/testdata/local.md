<!-- tfplan-triage:default -->
### Terraform plan triage

**1 medium** · 4 changes (+1 ~1 -/+2) · 1 resource changed outside Terraform

| Severity | What happens | Resource |
|---|---|---|
| medium | Deleted outside Terraform | `local_file.feature_flags` |

<details><summary>Why these were flagged</summary>

**`local_file.feature_flags`** (medium, drift)
- Deleted outside Terraform
- If the configuration still declares it, this plan recreates it.

</details>

<details><summary>4 lower-risk changes</summary>

**Low / info**
- `local_file.routing`: Replaces local_file (forced by `content`)
- `random_password.webhook_secret`: Replaces random_password (forced by `keepers`)

**Other changes** (2)
- create `local_file.feature_flags`
- update `terraform_data.release`

</details>

<sub>tfplan-triage · plan from Terraform/OpenTofu 1.16.5 · rule-based, not a substitute for reading the plan</sub>
