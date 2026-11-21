#
# Jarvis host network
#
# A small, dedicated VPC for the Jarvis host only, so it doesn't share a network with anything else in the account.
#
# - public:  the NAT gateway only. Don't launch instances here.
# - private: the Jarvis host. Default route to the NAT, so the host reaches Slack, Anthropic, SSM and package/image
#            registries from one static EIP. No inbound path from the internet.

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  name          = var.name
  cidr_block    = var.vpc_cidr
  instance_type = var.instance_type

  # One AZ, picked from those that actually offer the instance type
  az = sort(data.aws_ec2_instance_type_offerings.this.locations)[0]

  subnets = {
    public  = cidrsubnet(local.cidr_block, 2, 0) # first /26 of a /24
    private = cidrsubnet(local.cidr_block, 2, 1) # second /26
  }
}

data "aws_ec2_instance_type_offerings" "this" {
  location_type = "availability-zone"

  filter {
    name   = "instance-type"
    values = [local.instance_type]
  }
}

resource "aws_vpc" "this" {
  cidr_block = local.cidr_block

  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = local.name
  }
}

# Strip every rule from the default security group, so anything launched without one gets no network access
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.name}-default-do-not-use"
  }
}

resource "aws_subnet" "this" {
  for_each = local.subnets

  availability_zone = local.az
  cidr_block        = each.value
  vpc_id            = aws_vpc.this.id

  tags = {
    Name = "${local.name}-${each.key}"
    Tier = each.key
  }
}

## Internet and NAT

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = local.name
  }
}

# Static egress IP. Slack token IP restrictions and vendor allowlists for Jarvis point at this address.
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${local.name}-nat"
  }
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.this["public"].id

  tags = {
    Name = local.name
  }

  depends_on = [aws_internet_gateway.this]
}

## Routing

resource "aws_route_table" "this" {
  for_each = local.subnets

  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.name}-${each.key}"
    Tier = each.key
  }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.this["public"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.this["private"].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "this" {
  for_each = local.subnets

  route_table_id = aws_route_table.this[each.key].id
  subnet_id      = aws_subnet.this[each.key].id
}

## Flow logs
#
# Every accepted and rejected flow, so we can see what the Jarvis host actually talks to before the egress allowlist
# is written.

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${local.name}/vpc-flow-logs"
  retention_in_days = var.flow_log_retention_days
}

data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    sid = "WriteFlowLogs"

    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name}-vpc-flow-logs"

  assume_role_policy   = data.aws_iam_policy_document.flow_logs_assume_role.json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name}-vpc-flow-logs"

  policy = data.aws_iam_policy_document.flow_logs.json
  role   = aws_iam_role.flow_logs.id
}

resource "aws_flow_log" "this" {
  vpc_id       = aws_vpc.this.id
  traffic_type = "ALL"

  iam_role_arn             = aws_iam_role.flow_logs.arn
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  max_aggregation_interval = 60

  tags = {
    Name = local.name
  }
}
