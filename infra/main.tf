terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azapi" {}

data "azurerm_client_config" "current" {}

locals {
  name       = var.prefix
  table_name = "SOCLabAuth_CL"
  stream     = "Custom-${local.table_name}"
  tags       = { project = "sentinel-soc-lab" }
}

# ---------------------------------------------------------------------------
# Core: resource group, Log Analytics workspace, Sentinel
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-${local.name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}

# ---------------------------------------------------------------------------
# Custom table for synthetic identity logs
# ---------------------------------------------------------------------------
locals {
  auth_columns = [
    { name = "TimeGenerated", type = "datetime" },
    { name = "EventType", type = "string" },         # SignIn | RoleAssignment
    { name = "UserPrincipalName", type = "string" },
    { name = "SourceIP", type = "string" },
    { name = "Country", type = "string" },
    { name = "City", type = "string" },
    { name = "Result", type = "string" },            # Success | Failure
    { name = "FailureReason", type = "string" },
    { name = "Application", type = "string" },
    { name = "DeviceName", type = "string" },
    { name = "TargetRole", type = "string" },
    { name = "InitiatedBy", type = "string" },
  ]
}

resource "azapi_resource" "auth_table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = local.table_name
  parent_id = azurerm_log_analytics_workspace.law.id
  body = {
    properties = {
      retentionInDays = 30
      schema = {
        name    = local.table_name
        columns = local.auth_columns
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Logs Ingestion API: DCE + DCR for the custom table
# ---------------------------------------------------------------------------
resource "azurerm_monitor_data_collection_endpoint" "dce" {
  name                = "dce-${local.name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.tags
}

resource "azurerm_monitor_data_collection_rule" "auth" {
  name                        = "dcr-${local.name}-auth"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.dce.id

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
      name                  = "law"
    }
  }

  data_flow {
    streams       = [local.stream]
    destinations  = ["law"]
    output_stream = local.stream
    transform_kql = "source"
  }

  stream_declaration {
    stream_name = local.stream
    dynamic "column" {
      for_each = local.auth_columns
      content {
        name = column.value.name
        type = column.value.type
      }
    }
  }

  depends_on = [azapi_resource.auth_table]
  tags       = local.tags
}

# Lets the signed-in user (DefaultAzureCredential / az login) push logs.
resource "azurerm_role_assignment" "dcr_publisher" {
  scope                = azurerm_monitor_data_collection_rule.auth.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ---------------------------------------------------------------------------
# Lab Windows VM (optional) with Azure Monitor Agent -> SecurityEvent
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "vnet" {
  count               = var.deploy_vm ? 1 : 0
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.50.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "snet" {
  count                = var.deploy_vm ? 1 : 0
  name                 = "snet-lab"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet[0].name
  address_prefixes     = ["10.50.1.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  count               = var.deploy_vm ? 1 : 0
  name                = "nsg-${local.name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  # RDP only from YOUR public IP. Never open this to the internet.
  security_rule {
    name                       = "Allow-RDP-From-My-IP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.my_public_ip
    destination_address_prefix = "*"
  }
  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "assoc" {
  count                     = var.deploy_vm ? 1 : 0
  subnet_id                 = azurerm_subnet.snet[0].id
  network_security_group_id = azurerm_network_security_group.nsg[0].id
}

resource "azurerm_public_ip" "pip" {
  count               = var.deploy_vm ? 1 : 0
  name                = "pip-${local.name}-vm"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "nic" {
  count               = var.deploy_vm ? 1 : 0
  name                = "nic-${local.name}-vm"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.snet[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip[0].id
  }
  tags = local.tags
}

resource "azurerm_windows_virtual_machine" "vm" {
  count                 = var.deploy_vm ? 1 : 0
  name                  = "lab-vm01"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  size                  = var.vm_size
  admin_username        = var.admin_username
  admin_password        = var.admin_password
  network_interface_ids = [azurerm_network_interface.nic[0].id]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
  tags = local.tags
}

resource "azurerm_virtual_machine_extension" "ama" {
  count                      = var.deploy_vm ? 1 : 0
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.vm[0].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
}

resource "azurerm_monitor_data_collection_rule" "winsec" {
  count               = var.deploy_vm ? 1 : 0
  name                = "dcr-${local.name}-winsec"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
      name                  = "law"
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["law"]
  }

  data_sources {
    windows_event_log {
      name    = "security-events"
      streams = ["Microsoft-SecurityEvent"]
      # 4624 logon, 4625 failed logon, 4688 process create,
      # 4720 user created, 4732 member added to local group
      x_path_queries = [
        "Security!*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732)]]"
      ]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.sentinel]
  tags       = local.tags
}

resource "azurerm_monitor_data_collection_rule_association" "winsec" {
  count                   = var.deploy_vm ? 1 : 0
  name                    = "dcra-${local.name}-winsec"
  target_resource_id      = azurerm_windows_virtual_machine.vm[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.winsec[0].id
}
