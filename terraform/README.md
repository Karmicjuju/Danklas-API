# Danklas API Terraform Configuration

This directory contains Terraform configuration for deploying the simplified Danklas API infrastructure.

## Architecture

The infrastructure includes:
- **IAM Role and Policies**: For Bedrock Knowledge Base access and CloudWatch logging
- **CloudWatch Log Group**: For application logs (30-day retention)
- **ECS Task Definition**: Example containerized deployment configuration

## Key Features

- **Minimal IAM Permissions**: Only what's needed for Bedrock queries and logging
- **Bedrock Integration**: Full access to Knowledge Bases and Foundation Models
- **Guardrail Support**: Access to Bedrock Guardrails for content filtering
- **Container Ready**: ECS Fargate task definition included

## Environment Variables

The ECS task definition references these SSM parameters:
- `/danklas/okta/issuer` - Okta OIDC issuer URL
- `/danklas/okta/audience` - Okta OIDC audience
- `/danklas/bedrock/guardrail-id` - Bedrock Guardrail ID
- `/danklas/bedrock/guardrail-version` - Bedrock Guardrail Version

## Deployment

1. Update the S3 bucket name in the backend configuration
2. Create the required SSM parameters
3. Update the ECR image URL in the task definition
4. Deploy:

```bash
terraform init
terraform plan
terraform apply
```

## Simplified Design

This configuration has been significantly simplified from the original:
- **No API Gateway**: Deploy behind ALB or use direct container access
- **No VPC Endpoints**: Uses default VPC or existing networking
- **No Multi-Region**: Single region deployment
- **No Rate Limiting**: Application handles this if needed
- **No SSM Dependencies**: Guardrails are static environment variables

The focus is on core Bedrock integration with minimal operational overhead.