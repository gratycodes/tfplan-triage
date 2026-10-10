resource "azurerm_resource_group" "payments" {
  name     = "rg-payments-prod"
  location = "westeurope"
}

resource "azurerm_storage_account" "ledger" {
  name                     = "acmeledgerprod"
  resource_group_name      = azurerm_resource_group.payments.name
  location                 = azurerm_resource_group.payments.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
}

resource "azurerm_key_vault" "app" {
  name                = "kv-acme-app-prod"
  resource_group_name = azurerm_resource_group.payments.name
  location            = azurerm_resource_group.payments.location
  tenant_id           = "11111111-1111-1111-1111-111111111111"
  sku_name            = "standard"
}

resource "azurerm_network_security_group" "api" {
  name                = "nsg-api"
  resource_group_name = azurerm_resource_group.payments.name
  location            = azurerm_resource_group.payments.location
  tags                = { team = "payments" }
}
