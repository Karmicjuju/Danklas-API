# SSM Parameters for secure environment variables
resource "aws_ssm_parameter" "okta_issuer" {
  name  = "/${local.name}/okta/issuer"
  type  = "SecureString"
  value = var.okta_issuer

  tags = local.common_tags
}

resource "aws_ssm_parameter" "okta_audience" {
  name  = "/${local.name}/okta/audience"
  type  = "SecureString"
  value = var.okta_audience

  tags = local.common_tags
}

resource "aws_ssm_parameter" "bedrock_guardrail_id" {
  name  = "/${local.name}/bedrock/guardrail-id"
  type  = "SecureString"
  value = var.bedrock_guardrail_id

  tags = local.common_tags
}

resource "aws_ssm_parameter" "bedrock_guardrail_version" {
  name  = "/${local.name}/bedrock/guardrail-version"
  type  = "String"
  value = var.bedrock_guardrail_version

  tags = local.common_tags
}