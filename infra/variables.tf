variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "prefix" {
  description = "Short name used in resource names"
  type        = string
  default     = "soclab"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "deploy_vm" {
  description = "Deploy the Windows lab VM (SecurityEvent data source)"
  type        = bool
  default     = true
}

variable "vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "my_public_ip" {
  description = "Your public IP in CIDR form, e.g. 203.0.113.10/32 (curl ifconfig.me)"
  type        = string
}

variable "admin_username" {
  type    = string
  default = "labadmin"
}

variable "admin_password" {
  description = "VM admin password (12+ chars, complex)"
  type        = string
  sensitive   = true
}
