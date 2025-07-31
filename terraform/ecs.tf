module "ecs" {
  source  = "terraform-aws-modules/ecs/aws"
  version = "~> 5.0"

  cluster_name = local.name

  cluster_configuration = {
    execute_command_configuration = {
      logging = "OVERRIDE"
      log_configuration = {
        cloud_watch_log_group_name = "/aws/ecs/${local.name}"
      }
    }
  }

  fargate_capacity_providers = {
    FARGATE = {
      default_capacity_provider_strategy = {
        weight = 50
        base   = 20
      }
    }
    FARGATE_SPOT = {
      default_capacity_provider_strategy = {
        weight = 50
      }
    }
  }

  services = {
    danklas-api = {
      cpu    = var.cpu
      memory = var.memory

      container_definitions = {
        danklas-api = {
          cpu       = var.cpu
          memory    = var.memory
          essential = true
          image     = "${aws_ecr_repository.app.repository_url}:latest"

          port_mappings = [
            {
              name          = "danklas-api"
              containerPort = var.container_port
              hostPort      = var.container_port
              protocol      = "tcp"
            }
          ]

          environment = [
            {
              name  = "DANKLAS_ENV"
              value = var.environment
            },
            {
              name  = "AWS_REGION"
              value = var.region
            }
          ]

          secrets = [
            {
              name      = "OKTA_ISSUER"
              valueFrom = aws_ssm_parameter.okta_issuer.arn
            },
            {
              name      = "OKTA_AUDIENCE"
              valueFrom = aws_ssm_parameter.okta_audience.arn
            },
            {
              name      = "BEDROCK_GUARDRAIL_ID"
              valueFrom = aws_ssm_parameter.bedrock_guardrail_id.arn
            },
            {
              name      = "BEDROCK_GUARDRAIL_VERSION"
              valueFrom = aws_ssm_parameter.bedrock_guardrail_version.arn
            }
          ]

          health_check = {
            command     = ["CMD-SHELL", "curl -f http://localhost:${var.container_port}${var.health_check_path} || exit 1"]
            interval    = 30
            timeout     = 5
            retries     = 3
            startPeriod = 60
          }

          log_configuration = {
            logDriver = "awslogs"
            options = {
              awslogs-group         = "/aws/ecs/${local.name}"
              awslogs-region        = var.region
              awslogs-stream-prefix = "ecs"
            }
          }
        }
      }

      service_connect_configuration = {
        namespace = aws_service_discovery_http_namespace.this.arn
        service = {
          client_alias = {
            port     = var.container_port
            dns_name = local.name
          }
          port_name      = "danklas-api"
          discovery_name = local.name
        }
      }

      load_balancer = {
        service = {
          target_group_arn = module.alb.target_groups["ex_ecs"].arn
          container_name   = "danklas-api"
          container_port   = var.container_port
        }
      }

      subnet_ids = module.vpc.private_subnets
      security_group_rules = {
        alb_ingress = {
          type                     = "ingress"
          from_port                = var.container_port
          to_port                  = var.container_port
          protocol                 = "tcp"
          description              = "Service port"
          source_security_group_id = module.alb.security_group_id
        }
        egress_https = {
          type        = "egress"
          from_port   = 443
          to_port     = 443
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "HTTPS outbound for AWS services and OKTA"
        }
        egress_http = {
          type        = "egress"
          from_port   = 80
          to_port     = 80
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "HTTP outbound for health checks"
        }
        egress_dns = {
          type        = "egress"
          from_port   = 53
          to_port     = 53
          protocol    = "udp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "DNS resolution"
        }
      }

      desired_count    = var.desired_count
      assign_public_ip = false

      tags = local.common_tags
    }
  }

  tags = local.common_tags
}

resource "aws_service_discovery_http_namespace" "this" {
  name        = local.name
  description = "CloudMap namespace for ${local.name}"
  tags        = local.common_tags
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/aws/ecs/${local.name}"
  retention_in_days = 7

  tags = local.common_tags
}