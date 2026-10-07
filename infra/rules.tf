# Scheduled analytics rules. Each query lives in ../detections/*.kql

locals {
  account_ip = [
    { entity_type = "Account", identifier = "FullName", column_name = "UserPrincipalName" },
    { entity_type = "IP", identifier = "Address", column_name = "SourceIP" },
  ]

  rules = {
    bruteforce_success = {
      display_name = "SOCLab - Brute force followed by successful sign-in"
      severity     = "High"
      file         = "01-bruteforce-then-success.kql"
      frequency    = "PT15M"
      period       = "PT1H"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
      entities     = local.account_ip
      windows      = false
    }
    password_spray = {
      display_name = "SOCLab - Password spray from single IP"
      severity     = "Medium"
      file         = "02-password-spray.kql"
      frequency    = "PT15M"
      period       = "PT1H"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
      entities     = [{ entity_type = "IP", identifier = "Address", column_name = "SourceIP" }]
      windows      = false
    }
    impossible_travel = {
      display_name = "SOCLab - Impossible travel"
      severity     = "Medium"
      file         = "03-impossible-travel.kql"
      frequency    = "PT30M"
      period       = "PT2H"
      tactics      = ["InitialAccess"]
      techniques   = ["T1078"]
      entities     = local.account_ip
      windows      = false
    }
    offhours_priv_role = {
      display_name = "SOCLab - Privileged role assigned outside business hours"
      severity     = "High"
      file         = "04-offhours-privileged-role.kql"
      frequency    = "PT15M"
      period       = "PT1H"
      tactics      = ["Persistence", "PrivilegeEscalation"]
      techniques   = ["T1098"]
      entities = [
        { entity_type = "Account", identifier = "FullName", column_name = "UserPrincipalName" },
        { entity_type = "Account", identifier = "FullName", column_name = "InitiatedBy" },
      ]
      windows = false
    }
    win_failed_logons = {
      display_name = "SOCLab - Multiple failed Windows logons"
      severity     = "Medium"
      file         = "05-windows-failed-logons.kql"
      frequency    = "PT10M"
      period       = "PT30M"
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
      entities = [
        { entity_type = "Host", identifier = "HostName", column_name = "Computer" },
        { entity_type = "Account", identifier = "Name", column_name = "TargetAccount" },
        { entity_type = "IP", identifier = "Address", column_name = "IpAddress" },
      ]
      windows = true
    }
    win_local_admin_add = {
      display_name = "SOCLab - User added to local Administrators"
      severity     = "High"
      file         = "06-windows-local-admin-added.kql"
      frequency    = "PT10M"
      period       = "PT30M"
      tactics      = ["Persistence"]
      techniques   = ["T1098"]
      entities = [
        { entity_type = "Host", identifier = "HostName", column_name = "Computer" },
        { entity_type = "Account", identifier = "Name", column_name = "SubjectAccount" },
      ]
      windows = true
    }
  }

  # Skip Windows rules when no VM is deployed (SecurityEvent table won't exist).
  active_rules = { for k, v in local.rules : k => v if var.deploy_vm || !v.windows }
}

resource "azurerm_sentinel_alert_rule_scheduled" "rule" {
  for_each = local.active_rules

  name                       = "soclab-${replace(each.key, "_", "-")}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = each.value.display_name
  severity                   = each.value.severity
  query                      = file("${path.module}/../detections/${each.value.file}")
  query_frequency            = each.value.frequency
  query_period               = each.value.period
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques
  suppression_enabled        = false

  dynamic "entity_mapping" {
    for_each = each.value.entities
    content {
      entity_type = entity_mapping.value.entity_type
      field_mapping {
        identifier  = entity_mapping.value.identifier
        column_name = entity_mapping.value.column_name
      }
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }

  depends_on = [
    azapi_resource.auth_table,
    azurerm_monitor_data_collection_rule_association.winsec,
  ]
}
