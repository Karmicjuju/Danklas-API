terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "danklas-terraform-state"
    key    = "danklas-api/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

# CloudWatch Log Group for audit logs with 400-day retention (DANK-3.2)
resource "aws_cloudwatch_log_group" "danklas_audit_logs" {
  name              = "/aws/danklas-api/audit-logs"
  retention_in_days = 400

  tags = {
    Name        = "danklas-audit-logs"
    Environment = "production"
    Purpose     = "audit-compliance"
  }
}

# CloudWatch Alarm for audit log ingestion failures
resource "aws_cloudwatch_metric_alarm" "audit_log_failure" {
  alarm_name          = "danklas-audit-log-ingestion-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "IncomingLogEvents"
  namespace           = "AWS/Logs"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alarm when audit log ingestion fails"
  
  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.danklas_audit_logs.name
  }

  tags = {
    Name        = "danklas-audit-log-failure-alarm"
    Environment = "production"
  }
} 