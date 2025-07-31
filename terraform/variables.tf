variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "danklas-api"
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8000
}

variable "cpu" {
  description = "CPU units for the task"
  type        = number
  default     = 256
}

variable "memory" {
  description = "Memory for the task in MB"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "Desired number of tasks"
  type        = number
  default     = 2
}

variable "health_check_path" {
  description = "Health check path"
  type        = string
  default     = "/health"
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

variable "rate_limit_requests" {
  description = "Number of requests allowed per 5 minute window"
  type        = number
  default     = 100
}

variable "lambda_in_vpc" {
  description = "Whether to deploy Lambda authorizer in VPC"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}