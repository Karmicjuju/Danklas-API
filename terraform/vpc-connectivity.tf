# VPC Connectivity Configuration for Danklas API
# DANK-7.1: VPC Interface Endpoints for private API access
# DANK-7.2: Transit Gateway routes and Security Group rules

# VPC configuration for Danklas API
resource "aws_vpc" "danklas_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "danklas-api-vpc"
    Environment = "production"
    Service     = "danklas-api"
  }
}

# Private subnets for VPC endpoints
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.danklas_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "danklas-private-subnet-a"
    Type = "private"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.danklas_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "danklas-private-subnet-b"
    Type = "private"
  }
}

# Public subnets for NAT gateways
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.danklas_vpc.id
  cidr_block              = "10.0.101.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "danklas-public-subnet-a"
    Type = "public"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.danklas_vpc.id
  cidr_block              = "10.0.102.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "danklas-public-subnet-b"
    Type = "public"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "danklas_igw" {
  vpc_id = aws_vpc.danklas_vpc.id

  tags = {
    Name = "danklas-igw"
  }
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.danklas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.danklas_igw.id
  }

  tags = {
    Name = "danklas-public-rt"
  }
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# Security Group for VPC Endpoints (DANK-7.1)
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "danklas-vpc-endpoints-"
  vpc_id      = aws_vpc.danklas_vpc.id
  description = "Security group for Danklas API VPC endpoints"

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.danklas_vpc.cidr_block]
  }

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.danklas_vpc.cidr_block]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "danklas-vpc-endpoints-sg"
    Environment = "production"
  }
}

# Security Group for API Gateway VPC endpoint access
resource "aws_security_group" "api_access" {
  name_prefix = "danklas-api-access-"
  vpc_id      = aws_vpc.danklas_vpc.id
  description = "Security group for accessing Danklas API via VPC endpoint"

  egress {
    description     = "HTTPS to VPC endpoints"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }

  egress {
    description     = "HTTP to VPC endpoints"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }

  tags = {
    Name        = "danklas-api-access-sg"
    Environment = "production"
  }
}

# VPC Endpoint for API Gateway (DANK-7.1)
resource "aws_vpc_endpoint" "api_gateway" {
  vpc_id              = aws_vpc.danklas_vpc.id
  service_name        = "com.amazonaws.us-east-1.execute-api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "execute-api:Invoke"
        ]
        Resource = [
          "${aws_api_gateway_rest_api.danklas_api.execution_arn}/*"
        ]
      }
    ]
  })

  tags = {
    Name        = "danklas-api-gateway-endpoint"
    Environment = "production"
  }
}

# VPC Endpoint for SSM (for guardrails)
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.danklas_vpc.id
  service_name        = "com.amazonaws.us-east-1.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "danklas-ssm-endpoint"
    Environment = "production"
  }
}

# VPC Endpoint for CloudWatch Logs
resource "aws_vpc_endpoint" "cloudwatch_logs" {
  vpc_id              = aws_vpc.danklas_vpc.id
  service_name        = "com.amazonaws.us-east-1.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "danklas-cloudwatch-logs-endpoint"
    Environment = "production"
  }
}

# Transit Gateway for multi-VPC connectivity (DANK-7.2)
resource "aws_ec2_transit_gateway" "danklas_tgw" {
  description                     = "Transit Gateway for Danklas API connectivity"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"
  dns_support                     = "enable"
  vpn_ecmp_support               = "enable"

  tags = {
    Name        = "danklas-transit-gateway"
    Environment = "production"
  }
}

# Transit Gateway VPC attachment
resource "aws_ec2_transit_gateway_vpc_attachment" "danklas_vpc" {
  subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  transit_gateway_id = aws_ec2_transit_gateway.danklas_tgw.id
  vpc_id             = aws_vpc.danklas_vpc.id

  tags = {
    Name = "danklas-vpc-attachment"
  }
}

# Route table for private subnets with TGW routes
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.danklas_vpc.id

  # Route to other VPCs via Transit Gateway
  route {
    cidr_block         = "10.1.0.0/16"  # Example: other organization VPCs
    transit_gateway_id = aws_ec2_transit_gateway.danklas_tgw.id
  }

  tags = {
    Name = "danklas-private-rt"
  }
}

# Associate private subnets with private route table
resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# VPC Flow Logs for network monitoring
resource "aws_flow_log" "danklas_vpc" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.danklas_vpc.id
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/danklas-api/vpc-flow-logs"
  retention_in_days = 30

  tags = {
    Name        = "danklas-vpc-flow-logs"
    Environment = "production"
  }
}

# IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_log_role" {
  name = "danklas-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "danklas-vpc-flow-log-role"
  }
}

# IAM policy for VPC Flow Logs
resource "aws_iam_role_policy" "flow_log_policy" {
  name = "danklas-vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Outputs for VPC connectivity
output "vpc_id" {
  description = "ID of the Danklas API VPC"
  value       = aws_vpc.danklas_vpc.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

output "vpc_endpoint_dns_names" {
  description = "DNS names of VPC endpoints"
  value = {
    api_gateway     = aws_vpc_endpoint.api_gateway.dns_entry[0]["dns_name"]
    ssm             = aws_vpc_endpoint.ssm.dns_entry[0]["dns_name"]
    cloudwatch_logs = aws_vpc_endpoint.cloudwatch_logs.dns_entry[0]["dns_name"]
  }
}

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.danklas_tgw.id
}

output "security_group_ids" {
  description = "Security group IDs for VPC access"
  value = {
    vpc_endpoints = aws_security_group.vpc_endpoints.id
    api_access    = aws_security_group.api_access.id
  }
} 