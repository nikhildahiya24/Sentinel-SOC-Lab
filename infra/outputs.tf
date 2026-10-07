output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.law.name
}

output "dce_endpoint" {
  value = azurerm_monitor_data_collection_endpoint.dce.logs_ingestion_endpoint
}

output "dcr_immutable_id" {
  value = azurerm_monitor_data_collection_rule.auth.immutable_id
}

output "stream_name" {
  value = local.stream
}

output "vm_public_ip" {
  value = var.deploy_vm ? azurerm_public_ip.pip[0].ip_address : null
}
