# PR: "Rename storage to the new naming standard, retire the old vault,
# let support RDP into the jump box, give CI rights to manage RBAC"

resource "azurerm_resource_group" "payments" {
  name     = "rg-payments-prod"
  location = "westeurope"
}

resource "azurerm_storage_account" "ledger" {
  name                     = "stacmeledgerweu"
  resource_group_name      = azurerm_resource_group.payments.name
  location                 = azurerm_resource_group.payments.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
}

resource "azurerm_network_security_group" "api" {
  name                = "nsg-api"
  resource_group_name = azurerm_resource_group.payments.name
  location            = azurerm_resource_group.payments.location
  tags                = { team = "payments", owner = "platform" }
}

resource "azurerm_network_security_rule" "rdp" {
  name                        = "allow-rdp"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.payments.name
  network_security_group_name = azurerm_network_security_group.api.name
}

resource "azurerm_public_ip" "jump" {
  name                = "pip-jump"
  resource_group_name = azurerm_resource_group.payments.name
  location            = azurerm_resource_group.payments.location
  allocation_method   = "Static"
}

resource "azurerm_role_assignment" "ci_uaa" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000"
  role_definition_name = "User Access Administrator"
  principal_id         = "33333333-3333-3333-3333-333333333333"
}
