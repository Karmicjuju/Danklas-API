terraform {
  cloud {
    organization = "your-terraform-cloud-org"

    workspaces {
      name = "danklas-api-prod"
    }
  }
}

provider "aws" {
  region = var.region
}

module "danklas_api" {
  source = "../.."

  project_name  = "danklas-api"
  environment   = "prod"
  region        = var.region
  vpc_cidr      = "10.1.0.0/16"
  desired_count = 3

  # Production sizing
  cpu    = 512
  memory = 1024

  # Security Configuration
  okta_issuer               = var.okta_issuer
  okta_audience             = var.okta_audience
  bedrock_guardrail_id      = var.bedrock_guardrail_id
  bedrock_guardrail_version = var.bedrock_guardrail_version

  # Rate limiting (stricter for prod)
  rate_limit_requests = 100

  tags = {
    Environment = "prod"
    Project     = "danklas-api"
    Owner       = "platform-team"
    Critical    = "true"
  }
}