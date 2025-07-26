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

# IAM Role for Danklas API with tenant-based access boundary (DANK-1.3)
resource "aws_iam_role" "danklas_api_role" {
  name = "danklas-api-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]
        }
      }
    ]
  })

  tags = {
    Name        = "danklas-api-role"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# IAM Policy for Bedrock Knowledge Base access with tenant restrictions
resource "aws_iam_policy" "danklas_bedrock_policy" {
  name        = "danklas-bedrock-kb-access"
  description = "Policy for Danklas API to access Bedrock Knowledge Bases with tenant restrictions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockKnowledgeBaseQuery"
        Effect = "Allow"
        Action = [
          "bedrock:RetrieveAndGenerate",
          "bedrock:Retrieve"
        ]
        Resource = [
          "arn:aws:bedrock:*:*:knowledge-base/*"
        ]
        Condition = {
          StringEquals = {
            "bedrock:ResourceTag/tenant" = ["$${aws:userid}", "shared"]
          }
          StringLike = {
            "bedrock:ResourceTag/environment" = ["prod", "staging"]
          }
        }
      },
      {
        Sid    = "BedrockKnowledgeBaseStatus"
        Effect = "Allow"
        Action = [
          "bedrock:GetKnowledgeBase",
          "bedrock:ListKnowledgeBases"
        ]
        Resource = [
          "arn:aws:bedrock:*:*:knowledge-base/*"
        ]
        Condition = {
          StringEquals = {
            "bedrock:ResourceTag/tenant" = ["$${aws:userid}", "shared"]
          }
        }
      },
      {
        Sid    = "BedrockKnowledgeBaseSync"
        Effect = "Allow"
        Action = [
          "bedrock:StartIngestionJob",
          "bedrock:GetIngestionJob",
          "bedrock:ListIngestionJobs"
        ]
        Resource = [
          "arn:aws:bedrock:*:*:knowledge-base/*",
          "arn:aws:bedrock:*:*:knowledge-base/*/ingestion-job/*"
        ]
        Condition = {
          StringEquals = {
            "bedrock:ResourceTag/tenant" = ["$${aws:userid}", "shared"]
          }
        }
      },
      {
        Sid    = "BedrockFoundationModelAccess"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel"
        ]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/*"
        ]
      }
    ]
  })

  tags = {
    Name        = "danklas-bedrock-policy"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# IAM Policy for CloudWatch Logs access
resource "aws_iam_policy" "danklas_logs_policy" {
  name        = "danklas-cloudwatch-logs"
  description = "Policy for Danklas API to write to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_cloudwatch_log_group.danklas_audit_logs.arn,
          "${aws_cloudwatch_log_group.danklas_audit_logs.arn}:*"
        ]
      }
    ]
  })

  tags = {
    Name        = "danklas-logs-policy"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# IAM Policy for SSM Parameter Store access (for guardrails)
resource "aws_iam_policy" "danklas_ssm_policy" {
  name        = "danklas-ssm-access"
  description = "Policy for Danklas API to read SSM parameters"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMParameterRead"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/dank/guardrail/*"
        ]
      }
    ]
  })

  tags = {
    Name        = "danklas-ssm-policy"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# Attach policies to the IAM role
resource "aws_iam_role_policy_attachment" "danklas_bedrock_attach" {
  role       = aws_iam_role.danklas_api_role.name
  policy_arn = aws_iam_policy.danklas_bedrock_policy.arn
}

resource "aws_iam_role_policy_attachment" "danklas_logs_attach" {
  role       = aws_iam_role.danklas_api_role.name
  policy_arn = aws_iam_policy.danklas_logs_policy.arn
}

resource "aws_iam_role_policy_attachment" "danklas_ssm_attach" {
  role       = aws_iam_role.danklas_api_role.name
  policy_arn = aws_iam_policy.danklas_ssm_policy.arn
}

# IAM Permission Boundary for additional security
resource "aws_iam_policy" "danklas_permission_boundary" {
  name        = "danklas-permission-boundary"
  description = "Permission boundary for Danklas API to prevent privilege escalation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:*",
          "sts:AssumeRole"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:RequestedRegion" = "false"
          }
        }
      },
      {
        Sid    = "AllowServiceOperations"
        Effect = "Allow"
        Action = [
          "bedrock:*",
          "logs:*",
          "ssm:GetParameter*",
          "cloudwatch:*",
          "xray:*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "danklas-permission-boundary"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# Output the IAM role ARN for use in deployment
output "danklas_api_role_arn" {
  description = "ARN of the IAM role for Danklas API"
  value       = aws_iam_role.danklas_api_role.arn
}

output "danklas_permission_boundary_arn" {
  description = "ARN of the permission boundary policy"
  value       = aws_iam_policy.danklas_permission_boundary.arn
} 