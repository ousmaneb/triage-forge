variable "region" {
  type    = string
  default = "us-east-1"
}

variable "image_tag" {
  description = "Image tag to run on first apply. Later deploys come from the deploy workflow."
  type        = string
  default     = "bootstrap"
}

variable "cpu" {
  type    = number
  default = 512
}

variable "memory" {
  type    = number
  default = 1024
}

variable "desired_count" {
  description = "Set to 0 to stop paying for compute between demos (the load balancer still bills)."
  type        = number
  default     = 1
}

variable "llm_provider" {
  type    = string
  default = "anthropic"
}

variable "llm_model" {
  type    = string
  default = "claude-opus-5-5"
}

variable "llm_effort" {
  type    = string
  default = "medium"
}

variable "allowed_cidrs" {
  description = "Who may reach the load balancer. Narrow this to your SIEM's egress addresses."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "certificate_arn" {
  description = "ACM certificate for HTTPS. Leave empty for HTTP only."
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "owner/name of the GitHub repository allowed to deploy, e.g. ousmaneb/triage-forge. Empty skips the deploy role."
  type        = string
  default     = ""
}

variable "create_github_oidc_provider" {
  description = "Set false if the AWS account already has the GitHub OIDC provider."
  type        = bool
  default     = true
}
