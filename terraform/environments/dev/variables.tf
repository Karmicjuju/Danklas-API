variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "okta_issuer" {
  description = "Okta issuer URL"
  type        = string
  sensitive   = true
}

variable "okta_audience" {
  description = "Okta audience"
  type        = string
  sensitive   = true
}

variable "bedrock_guardrail_id" {
  description = "Bedrock guardrail ID"
  type        = string
  sensitive   = true
}

variable "bedrock_guardrail_version" {
  description = "Bedrock guardrail version"
  type        = string
  default     = "DRAFT"
}