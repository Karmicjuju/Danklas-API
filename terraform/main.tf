terraform {
  backend "s3" {
    bucket = "danklas-terraform-state"
    key    = "danklas-api/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

# CloudWatch Log Group for application logs
resource "aws_cloudwatch_log_group" "danklas_app_logs" {
  name              = "/aws/danklas-api/app-logs"
  retention_in_days = 30

  tags = {
    Name        = "danklas-app-logs"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# IAM Role for Danklas API 
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

# IAM Policy for Bedrock Knowledge Base access
resource "aws_iam_policy" "danklas_bedrock_policy" {
  name        = "danklas-bedrock-kb-access"
  description = "Policy for Danklas API to access Bedrock Knowledge Bases"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockKnowledgeBaseAccess"
        Effect = "Allow"
        Action = [
          "bedrock:RetrieveAndGenerate",
          "bedrock:Retrieve"
        ]
        Resource = [
          "arn:aws:bedrock:*:*:knowledge-base/*"
        ]
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
      },
      {
        Sid    = "BedrockGuardrailAccess"
        Effect = "Allow"
        Action = [
          "bedrock:GetGuardrail",
          "bedrock:ListGuardrails"
        ]
        Resource = [
          "arn:aws:bedrock:*:*:guardrail/*"
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
          aws_cloudwatch_log_group.danklas_app_logs.arn,
          "${aws_cloudwatch_log_group.danklas_app_logs.arn}:*"
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

# Attach policies to the IAM role
resource "aws_iam_role_policy_attachment" "danklas_bedrock_attach" {
  role       = aws_iam_role.danklas_api_role.name
  policy_arn = aws_iam_policy.danklas_bedrock_policy.arn
}

resource "aws_iam_role_policy_attachment" "danklas_logs_attach" {
  role       = aws_iam_role.danklas_api_role.name
  policy_arn = aws_iam_policy.danklas_logs_policy.arn
}

# Output the IAM role ARN for use in deployment
output "danklas_api_role_arn" {
  description = "ARN of the IAM role for Danklas API"
  value       = aws_iam_role.danklas_api_role.arn
}

# Example ECS Task Definition (if deploying on ECS)
resource "aws_ecs_task_definition" "danklas_api" {
  family                   = "danklas-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.danklas_api_role.arn
  task_role_arn            = aws_iam_role.danklas_api_role.arn

  container_definitions = jsonencode([
    {
      name  = "danklas-api"
      image = "your-ecr-repo/danklas-api:latest"

      portMappings = [
        {
          containerPort = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "DANKLAS_ENV"
          value = "prod"
        },
        {
          name  = "AWS_REGION"
          value = "us-east-1"
        }
      ]

      secrets = [
        {
          name      = "OKTA_ISSUER"
          valueFrom = "arn:aws:ssm:us-east-1:account:parameter/danklas/okta/issuer"
        },
        {
          name      = "OKTA_AUDIENCE"
          valueFrom = "arn:aws:ssm:us-east-1:account:parameter/danklas/okta/audience"
        },
        {
          name      = "BEDROCK_GUARDRAIL_ID"
          valueFrom = "arn:aws:ssm:us-east-1:account:parameter/danklas/bedrock/guardrail-id"
        },
        {
          name      = "BEDROCK_GUARDRAIL_VERSION"
          valueFrom = "arn:aws:ssm:us-east-1:account:parameter/danklas/bedrock/guardrail-version"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.danklas_app_logs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "ecs"
        }
      }

      essential = true
    }
  ])

  tags = {
    Name        = "danklas-api-task"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# Output task definition ARN
output "ecs_task_definition_arn" {
  description = "ARN of the ECS task definition"
  value       = aws_ecs_task_definition.danklas_api.arn
}