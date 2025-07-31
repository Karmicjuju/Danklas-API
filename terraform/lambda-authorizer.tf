# Lambda Authorizer IAM Role
resource "aws_iam_role" "lambda_authorizer_role" {
  name = "${local.name}-lambda-authorizer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Lambda basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_authorizer_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_authorizer_role.name
}

# Lambda VPC execution policy (if needed for VPC Lambda)
resource "aws_iam_role_policy_attachment" "lambda_authorizer_vpc" {
  count      = var.lambda_in_vpc ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
  role       = aws_iam_role.lambda_authorizer_role.name
}

# Additional permissions for SSM parameters
resource "aws_iam_role_policy" "lambda_authorizer_ssm" {
  name = "${local.name}-lambda-authorizer-ssm"
  role = aws_iam_role.lambda_authorizer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          aws_ssm_parameter.okta_issuer.arn,
          aws_ssm_parameter.okta_audience.arn
        ]
      }
    ]
  })
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_authorizer" {
  name              = "/aws/lambda/${local.name}-authorizer"
  retention_in_days = 7

  tags = local.common_tags
}

# Lambda function package
data "archive_file" "lambda_authorizer_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda-authorizer.zip"
  
  source {
    content = templatefile("${path.module}/../lambda/authorizer/lambda_function.py", {
      # Any template variables if needed
    })
    filename = "lambda_function.py"
  }
  
  source {
    content  = file("${path.module}/../lambda/authorizer/requirements.txt")
    filename = "requirements.txt"
  }
}

# Lambda function
resource "aws_lambda_function" "authorizer" {
  filename         = data.archive_file.lambda_authorizer_zip.output_path
  function_name    = "${local.name}-authorizer"
  role            = aws_iam_role.lambda_authorizer_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.11"
  timeout         = 30
  memory_size     = 256

  source_code_hash = data.archive_file.lambda_authorizer_zip.output_base64sha256

  environment {
    variables = {
      OKTA_ISSUER   = var.okta_issuer
      OKTA_AUDIENCE = var.okta_audience
      LOG_LEVEL     = var.environment == "prod" ? "INFO" : "DEBUG"
    }
  }

  # VPC configuration (optional)
  dynamic "vpc_config" {
    for_each = var.lambda_in_vpc ? [1] : []
    content {
      subnet_ids         = module.vpc.private_subnets
      security_group_ids = [aws_security_group.lambda_authorizer[0].id]
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_authorizer_basic,
    aws_cloudwatch_log_group.lambda_authorizer
  ]

  tags = local.common_tags
}

# Security group for Lambda (if in VPC)
resource "aws_security_group" "lambda_authorizer" {
  count       = var.lambda_in_vpc ? 1 : 0
  name        = "${local.name}-lambda-authorizer-sg"
  description = "Security group for Lambda authorizer"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound for Okta API calls"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP outbound"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name}-lambda-authorizer-sg"
  })
}

# Lambda permission for API Gateway to invoke
resource "aws_lambda_permission" "api_gateway_invoke_authorizer" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api_gateway.api_execution_arn}/*/*"
}

# Lambda alias for versioning
resource "aws_lambda_alias" "authorizer_live" {
  name             = "live"
  description      = "Live version of the authorizer"
  function_name    = aws_lambda_function.authorizer.function_name
  function_version = "$LATEST"

  lifecycle {
    ignore_changes = [function_version]
  }
}