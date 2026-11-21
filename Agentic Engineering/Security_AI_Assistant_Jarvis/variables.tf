variable "aws_region" {
  description = "Region for every resource in this stack."
  type        = string
  default     = "us-east-1"
}

variable "allowed_account_ids" {
  description = "AWS account IDs this stack may be applied to (guards against applying with the wrong profile). Empty allows any."
  type        = list(string)
  default     = []
}

variable "name" {
  description = "Name prefix for resources and Name tags."
  type        = string
  default     = "jarvis"
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated Jarvis VPC. Split into a public (NAT) and a private (host) /26."
  type        = string
  default     = "10.251.0.0/24"
}

variable "instance_type" {
  description = "Instance type for the Jarvis host (arm64: the AMI is AL2023 arm64)."
  type        = string
  default     = "t4g.large"
}

variable "data_volume_size_gb" {
  description = "Size of the HERMES_HOME data volume, which survives instance replacement."
  type        = number
  default     = 20
}

variable "secret_name" {
  description = "Secrets Manager secret holding the Slack, Anthropic and vendor credentials (read by hermes/bin/jarvis-secrets; set JARVIS_SECRET_ID in managed/host.env if you change it)."
  type        = string
  default     = "jarvis/prod/hermes"
}

variable "secret_kms_key_id" {
  description = "Customer-managed KMS key for the secret. Null uses the AWS-managed key, which any account admin can use to read the secret."
  type        = string
  default     = null
}

variable "ssm_session_log_group_name" {
  description = "Existing CloudWatch log group that Session Manager streams sessions to (configured account-wide, outside this stack). The host role may write to it."
  type        = string
  default     = "/ssm/sessions"
}

variable "flow_log_retention_days" {
  description = "Retention for the VPC flow log group."
  type        = number
  default     = 30
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary to attach to the IAM roles this stack creates, if your organisation requires one."
  type        = string
  default     = null
}

variable "default_tags" {
  description = "Tags applied to every resource by the AWS provider."
  type        = map(string)
  default = {
    provisioner = "terraform"
    app         = "jarvis"
  }
}
