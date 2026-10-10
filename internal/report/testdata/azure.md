<!-- tfplan-triage:default -->
### Terraform plan triage

**4 critical, 1 medium** · 6 changes (+3 ~1 -/+1 -1)

| Severity | What happens | Resource |
|---|---|---|
| **critical** | Deletes key: all keys, secrets and certificates in the vault | `azurerm_key_vault.app` |
| **critical** | Replaces storage account (forced by `name`): all blobs, files, queues and tables in the account | `azurerm_storage_account.ledger` |
| **critical** | Grants access: `User Access Administrator` at subscription or management-group scope (`/subscriptions/00000000-0000-0000-0000-000000000000`) | `azurerm_role_assignment.ci_uaa` |
| **critical** | Exposes: port 3389 (RDP) open to the internet (from `*`) | `azurerm_network_security_rule.rdp` |
| medium | Exposes: allocates a public IP | `azurerm_public_ip.jump` |

<details><summary>Why these were flagged</summary>

**`azurerm_key_vault.app`** (critical, destroy-stateful)
- Deletes key: all keys, secrets and certificates in the vault
- The resource block was removed from the configuration.
- `purge_protection_enabled` is off, so the provider will not stop it.

**`azurerm_storage_account.ledger`** (critical, destroy-stateful)
- Replaces storage account (forced by `name`): all blobs, files, queues and tables in the account
- `name`: "acmeledgerprod" → "stacmeledgerweu"
- The old object is destroyed before the new one exists.
- `lifecycle { prevent_destroy = true }` is not set in the source.

**`azurerm_role_assignment.ci_uaa`** (critical, iam-widening)
- Grants access: `User Access Administrator` at subscription or management-group scope (`/subscriptions/00000000-0000-0000-0000-000000000000`)

**`azurerm_network_security_rule.rdp`** (critical, network-exposure)
- Exposes: port 3389 (RDP) open to the internet (from `*`)

**`azurerm_public_ip.jump`** (medium, network-exposure)
- Exposes: allocates a public IP

</details>

<details><summary>1 lower-risk change</summary>

**Updates to tags only** (1)
`azurerm_network_security_group.api`

</details>

<sub>tfplan-triage · plan from Terraform/OpenTofu 1.16.5 · rule-based, not a substitute for reading the plan</sub>
