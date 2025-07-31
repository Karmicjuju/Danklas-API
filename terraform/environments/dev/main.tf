terraform {
  cloud {
    organization = "your-terraform-cloud-org"
    
    workspaces {
      name = "danklas-api-dev"
    }
  }
}

provider "aws" {
  region = var.region
}

module "danklas_api" {
  source = "../.."

  project_name    = "danklas-api"
  environment     = "dev"
  region          = var.region
  vpc_cidr        = "10.0.0.0/16"
  desired_count   = 1

  # Security Configuration
  okta_issuer                = var.okta_issuer
  okta_audience             = var.okta_audience
  bedrock_guardrail_id      = var.bedrock_guardrail_id
  bedrock_guardrail_version = var.bedrock_guardrail_version

  # Rate limiting (more lenient for dev)
  rate_limit_requests = 200

  tags = {
    Environment = "dev"
    Project     = "danklas-api"
    Owner       = "platform-team"
  }
}