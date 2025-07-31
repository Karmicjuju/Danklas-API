module "api_gateway" {
  source  = "terraform-aws-modules/apigateway-v2/aws"
  version = "~> 2.0"

  name          = local.name
  description   = "API Gateway for ${local.name}"
  protocol_type = "HTTP"

  cors_configuration = {
    allow_headers = ["content-type", "x-amz-date", "authorization", "x-api-key", "x-amz-security-token", "x-amz-user-agent"]
    allow_methods = ["*"]
    allow_origins = ["*"]
  }

  domain_name                 = var.environment == "prod" ? "${var.project_name}.yourdomain.com" : "${var.project_name}-${var.environment}.yourdomain.com"
  domain_name_certificate_arn = var.environment == "prod" ? aws_acm_certificate.main.arn : aws_acm_certificate.main.arn

  default_stage_access_log_destination_arn = aws_cloudwatch_log_group.api_gw.arn
  default_stage_access_log_format = jsonencode({
    requestId               = "$context.requestId"
    sourceIp                = "$context.identity.sourceIp"
    requestTime             = "$context.requestTime"
    protocol                = "$context.protocol"
    httpMethod              = "$context.httpMethod"
    resourcePath            = "$context.resourcePath"
    routeKey                = "$context.routeKey"
    status                  = "$context.status"
    responseLength          = "$context.responseLength"
    integrationErrorMessage = "$context.integrationErrorMessage"
    # Authorizer context
    authorizerError   = "$context.authorizer.error"
    authorizerLatency = "$context.authorizer.latency"
    authorizerStatus  = "$context.authorizer.status"
  })

  # Create Lambda authorizer
  authorizers = {
    "okta-jwt" = {
      authorizer_type                   = "REQUEST"
      authorizer_uri                    = aws_lambda_function.authorizer.invoke_arn
      authorizer_credentials_arn        = aws_iam_role.api_gateway_authorizer_role.arn
      authorizer_result_ttl_in_seconds  = 300
      authorizer_payload_format_version = "1.0"
      identity_sources                  = ["$request.header.Authorization"]
    }
  }

  integrations = {
    # Public endpoints (no auth required)
    "GET /" = {
      lambda_arn             = null
      payload_format_version = "1.0"
      timeout_milliseconds   = 30000

      connection_type = "VPC_LINK"
      vpc_link        = aws_apigatewayv2_vpc_link.this.id
      uri             = "http://${module.alb.dns_name}"
    }

    "GET /health" = {
      lambda_arn             = null
      payload_format_version = "1.0"
      timeout_milliseconds   = 30000

      connection_type = "VPC_LINK"
      vpc_link        = aws_apigatewayv2_vpc_link.this.id
      uri             = "http://${module.alb.dns_name}/health"
    }

    # Protected endpoints (require auth)
    "POST /knowledge-bases/{kb_id}/query" = {
      lambda_arn             = null
      payload_format_version = "1.0"
      timeout_milliseconds   = 30000

      connection_type = "VPC_LINK"
      vpc_link        = aws_apigatewayv2_vpc_link.this.id
      uri             = "http://${module.alb.dns_name}/knowledge-bases/{kb_id}/query"

      authorizer_key = "okta-jwt"
    }

    "POST /knowledge-bases/{kb_id}/refresh" = {
      lambda_arn             = null
      payload_format_version = "1.0"
      timeout_milliseconds   = 30000

      connection_type = "VPC_LINK"
      vpc_link        = aws_apigatewayv2_vpc_link.this.id
      uri             = "http://${module.alb.dns_name}/knowledge-bases/{kb_id}/refresh"

      authorizer_key = "okta-jwt"
    }

    "GET /knowledge-bases" = {
      lambda_arn             = null
      payload_format_version = "1.0"
      timeout_milliseconds   = 30000

      connection_type = "VPC_LINK"
      vpc_link        = aws_apigatewayv2_vpc_link.this.id
      uri             = "http://${module.alb.dns_name}/knowledge-bases"

      authorizer_key = "okta-jwt"
    }
  }

  tags = local.common_tags
}

resource "aws_apigatewayv2_vpc_link" "this" {
  name               = local.name
  security_group_ids = [module.vpc.default_security_group_id]
  subnet_ids         = module.vpc.private_subnets

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = 7

  tags = local.common_tags
}

# SSL Certificate for custom domain
resource "aws_acm_certificate" "main" {
  domain_name       = var.environment == "prod" ? "${var.project_name}.yourdomain.com" : "${var.project_name}-${var.environment}.yourdomain.com"
  validation_method = "DNS"

  subject_alternative_names = [
    var.environment == "prod" ? "www.${var.project_name}.yourdomain.com" : "www.${var.project_name}-${var.environment}.yourdomain.com"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# Route 53 zone and records for domain validation
data "aws_route53_zone" "main" {
  name         = "yourdomain.com"
  private_zone = false
}

resource "aws_route53_record" "main" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.main : record.fqdn]
}

# DNS record pointing to API Gateway
resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.environment == "prod" ? var.project_name : "${var.project_name}-${var.environment}"
  type    = "A"

  alias {
    name                   = module.api_gateway.domain_name_target_domain_name
    zone_id                = module.api_gateway.domain_name_hosted_zone_id
    evaluate_target_health = false
  }
}