# IAM role for API Gateway to invoke Lambda authorizer
resource "aws_iam_role" "api_gateway_authorizer_role" {
  name = "${local.name}-api-gateway-authorizer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Policy for API Gateway to invoke Lambda authorizer
resource "aws_iam_role_policy" "api_gateway_authorizer_invoke" {
  name = "${local.name}-api-gateway-authorizer-invoke"
  role = aws_iam_role.api_gateway_authorizer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.authorizer.arn,
          "${aws_lambda_function.authorizer.arn}:*"
        ]
      }
    ]
  })
}