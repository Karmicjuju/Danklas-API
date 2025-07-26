# Multi-Region Deployment Configuration for Danklas API
# DANK-6.1: Multi-region deployment with Route 53 latency routing
# DANK-6.2: Multi-region KMS keys for cross-region decrypt

# Primary region (us-east-1) - already configured in main.tf
# Secondary region configuration (us-east-2)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
      configuration_aliases = [aws.primary, aws.secondary]
    }
  }
}

# Primary region provider (us-east-1)
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
}

# Secondary region provider (us-east-2)  
provider "aws" {
  alias  = "secondary"
  region = "us-east-2"
}

# Multi-region KMS key for encryption (DANK-6.2)
resource "aws_kms_key" "danklas_multi_region" {
  provider                = aws.primary
  description             = "Multi-region KMS key for Danklas API"
  multi_region            = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowDanklasAPIAccess"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.danklas_api_role.arn
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "danklas-multi-region-key"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# KMS key alias
resource "aws_kms_alias" "danklas_multi_region" {
  provider      = aws.primary
  name          = "alias/danklas-multi-region"
  target_key_id = aws_kms_key.danklas_multi_region.key_id
}

# Replica key in secondary region
resource "aws_kms_replica_key" "danklas_secondary" {
  provider                = aws.secondary
  description             = "Danklas API multi-region key replica"
  primary_key_arn         = aws_kms_key.danklas_multi_region.arn
  deletion_window_in_days = 7

  tags = {
    Name        = "danklas-secondary-region-key"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# KMS key alias for secondary region
resource "aws_kms_alias" "danklas_secondary" {
  provider      = aws.secondary
  name          = "alias/danklas-secondary"
  target_key_id = aws_kms_replica_key.danklas_secondary.key_id
}

# Data source for current AWS account ID
data "aws_caller_identity" "current" {}

# Route 53 hosted zone for latency-based routing
resource "aws_route53_zone" "danklas_api" {
  name = var.domain_name

  tags = {
    Name        = "danklas-api-zone"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# Health checks for primary region
resource "aws_route53_health_check" "primary" {
  fqdn                            = "${var.primary_alb_dns_name}"
  port                            = 443
  type                            = "HTTPS"
  resource_path                   = "/health"
  failure_threshold               = 3
  request_interval                = 30
  cloudwatch_alarm_region         = "us-east-1"
  cloudwatch_alarm_name           = "danklas-primary-health"
  insufficient_data_health_status = "Failure"

  tags = {
    Name = "danklas-primary-health-check"
  }
}

# Health checks for secondary region
resource "aws_route53_health_check" "secondary" {
  fqdn                            = "${var.secondary_alb_dns_name}"
  port                            = 443
  type                            = "HTTPS"
  resource_path                   = "/health"
  failure_threshold               = 3
  request_interval                = 30
  cloudwatch_alarm_region         = "us-east-2"
  cloudwatch_alarm_name           = "danklas-secondary-health"
  insufficient_data_health_status = "Failure"

  tags = {
    Name = "danklas-secondary-health-check"
  }
}

# Primary region DNS record with latency routing
resource "aws_route53_record" "primary" {
  zone_id = aws_route53_zone.danklas_api.zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.primary_alb_dns_name
    zone_id                = var.primary_alb_zone_id
    evaluate_target_health = true
  }

  set_identifier = "primary"
  
  latency_routing_policy {
    region = "us-east-1"
  }

  health_check_id = aws_route53_health_check.primary.id
}

# Secondary region DNS record with latency routing
resource "aws_route53_record" "secondary" {
  zone_id = aws_route53_zone.danklas_api.zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.secondary_alb_dns_name
    zone_id                = var.secondary_alb_zone_id
    evaluate_target_health = true
  }

  set_identifier = "secondary"
  
  latency_routing_policy {
    region = "us-east-2"
  }

  health_check_id = aws_route53_health_check.secondary.id
}

# CloudWatch alarm for primary region health
resource "aws_cloudwatch_metric_alarm" "primary_health" {
  provider            = aws.primary
  alarm_name          = "danklas-primary-health"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthCheckStatus"
  namespace           = "AWS/Route53"
  period              = "60"
  statistic           = "Minimum"
  threshold           = "1"
  alarm_description   = "Primary region health check failure"
  treat_missing_data  = "breaching"

  dimensions = {
    HealthCheckId = aws_route53_health_check.primary.id
  }

  alarm_actions = [
    aws_sns_topic.alerts.arn
  ]

  tags = {
    Name        = "danklas-primary-health-alarm"
    Environment = "production"
  }
}

# CloudWatch alarm for secondary region health
resource "aws_cloudwatch_metric_alarm" "secondary_health" {
  provider            = aws.secondary
  alarm_name          = "danklas-secondary-health"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthCheckStatus"
  namespace           = "AWS/Route53"
  period              = "60"
  statistic           = "Minimum"
  threshold           = "1"
  alarm_description   = "Secondary region health check failure"
  treat_missing_data  = "breaching"

  dimensions = {
    HealthCheckId = aws_route53_health_check.secondary.id
  }

  alarm_actions = [
    aws_sns_topic.alerts_secondary.arn
  ]

  tags = {
    Name        = "danklas-secondary-health-alarm"
    Environment = "production"
  }
}

# SNS topic for alerts in primary region
resource "aws_sns_topic" "alerts" {
  provider = aws.primary
  name     = "danklas-api-alerts"

  tags = {
    Name        = "danklas-alerts"
    Environment = "production"
  }
}

# SNS topic for alerts in secondary region
resource "aws_sns_topic" "alerts_secondary" {
  provider = aws.secondary
  name     = "danklas-api-alerts-secondary"

  tags = {
    Name        = "danklas-alerts-secondary"
    Environment = "production"
  }
}

# Variables for multi-region configuration
variable "domain_name" {
  description = "Domain name for the API"
  type        = string
  default     = "danklas-api.com"
}

variable "primary_alb_dns_name" {
  description = "DNS name of the primary region ALB"
  type        = string
  default     = "danklas-api-primary-123456789.us-east-1.elb.amazonaws.com"
}

variable "primary_alb_zone_id" {
  description = "Zone ID of the primary region ALB"
  type        = string
  default     = "Z35SXDOTRQ7X7K"  # us-east-1 ALB zone ID
}

variable "secondary_alb_dns_name" {
  description = "DNS name of the secondary region ALB"
  type        = string
  default     = "danklas-api-secondary-123456789.us-east-2.elb.amazonaws.com"
}

variable "secondary_alb_zone_id" {
  description = "Zone ID of the secondary region ALB"
  type        = string
  default     = "Z3AADJGX6KTTL2"  # us-east-2 ALB zone ID
}

# Outputs for multi-region setup
output "multi_region_kms_key_arn" {
  description = "ARN of the multi-region KMS key"
  value       = aws_kms_key.danklas_multi_region.arn
}

output "secondary_kms_key_arn" {
  description = "ARN of the secondary region KMS key"
  value       = aws_kms_replica_key.danklas_secondary.arn
}

output "route53_zone_id" {
  description = "Route 53 hosted zone ID"
  value       = aws_route53_zone.danklas_api.zone_id
}

output "primary_health_check_id" {
  description = "Primary region health check ID"
  value       = aws_route53_health_check.primary.id
}

output "secondary_health_check_id" {
  description = "Secondary region health check ID"
  value       = aws_route53_health_check.secondary.id
} 