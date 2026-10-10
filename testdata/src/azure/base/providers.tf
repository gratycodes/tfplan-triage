terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "4.47.0" }
  }
}

# Synthetic identity: gen.sh runs fake_msi.py on localhost so the provider
# can configure; plans use -refresh=false and never call Azure.
provider "azurerm" {
  features {}
  subscription_id                 = "00000000-0000-0000-0000-000000000000"
  tenant_id                       = "11111111-1111-1111-1111-111111111111"
  use_msi                         = true
  msi_endpoint                    = "http://127.0.0.1:8765/metadata/identity/oauth2/token"
  resource_provider_registrations = "none"
}
