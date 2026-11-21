#
# Jarvis host
#
# One AL2023 arm64 instance running Jarvis (Hermes + jarvis-tools). Some hardening (egress allowlist, off-host audit
# trail, runtime security sensor, backups) isn't here yet (see README.md).
#
# Access is SSM Session Manager only: no public IP, no key pair, no inbound security group rules, sshd disabled.
# HERMES_HOME lives on a separate data volume that survives instance replacement.

# Session Manager logging is account-wide, so it is configured outside this stack. Built from the name rather than
# looked up, so this stack still plans before that log group exists.
locals {
  ssm_sessions_log_group_arn = "arn:aws:logs:${data.aws_region.current.region}:${local.account_id}:log-group:${var.ssm_session_log_group_name}"
}

## Security group

resource "aws_security_group" "host" {
  name = local.name

  description = "Jarvis host. No inbound, HTTPS out only."
  vpc_id      = aws_vpc.this.id
}

# Slack Socket Mode, Anthropic, SSM and package/image registries are all HTTPS. DNS (VPC resolver) and NTP (Amazon
# Time Sync) aren't filtered by security groups.
resource "aws_security_group_rule" "host_https_out" {
  type              = "egress"
  security_group_id = aws_security_group.host.id

  description = "HTTPS out"
  protocol    = "tcp"
  from_port   = 443
  to_port     = 443

  cidr_blocks = ["0.0.0.0/0"]
}

## Secrets
#
# Created empty. Set the value by hand (console or `aws secretsmanager put-secret-value`) as JSON with the keys
# slack_bot_token, slack_app_token and anthropic_api_key, plus one key per vendor credential (see README.md). Use a
# Slack app dedicated to Jarvis; never reuse a bot token another pipeline depends on.

resource "aws_secretsmanager_secret" "jarvis" {
  name = var.secret_name

  description             = "Jarvis: Slack app tokens, Anthropic key and vendor credentials"
  kms_key_id              = var.secret_kms_key_id
  recovery_window_in_days = 7
}

## IAM

data "aws_iam_policy_document" "host_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "host" {
  statement {
    sid = "ReadJarvisSecret"

    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.jarvis.arn]
  }

  statement {
    sid = "WriteSessionLogs"

    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = ["${local.ssm_sessions_log_group_arn}:*"]
  }

  # The SSM agent checks the log group exists before it streams a session
  statement {
    sid = "DescribeLogGroups"

    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "host" {
  name = local.name

  assume_role_policy   = data.aws_iam_policy_document.host_assume_role.json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy" "host" {
  name = local.name

  policy = data.aws_iam_policy_document.host.json
  role   = aws_iam_role.host.id
}

resource "aws_iam_role_policy_attachment" "host_ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "host" {
  name = local.name
  role = aws_iam_role.host.name
}

## Instance

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

data "aws_kms_alias" "ebs_default" {
  name = "alias/aws/ebs"
}

# HERMES_HOME. A separate volume so state survives instance replacement, and so only one instance can ever hold it
# (gp3 can't multi-attach), which keeps a single gateway on the app token.
resource "aws_ebs_volume" "data" {
  availability_zone = local.az

  encrypted  = true
  kms_key_id = data.aws_kms_alias.ebs_default.target_key_arn
  size       = var.data_volume_size_gb
  type       = "gp3"

  tags = {
    Name = "${local.name}-data"
  }
}

resource "aws_instance" "host" {
  ami                  = data.aws_ssm_parameter.al2023_arm64.value
  iam_instance_profile = aws_iam_instance_profile.host.name
  instance_type        = local.instance_type

  subnet_id                   = aws_subnet.this["private"].id
  vpc_security_group_ids      = [aws_security_group.host.id]
  associate_public_ip_address = false

  root_block_device {
    encrypted   = true
    kms_key_id  = data.aws_kms_alias.ebs_default.target_key_arn
    volume_size = 30
    volume_type = "gp3"

    tags = {
      Name = local.name
    }
  }

  # IMDSv2 only. A hop limit of 1 keeps containers on a Docker bridge from reaching the instance role (AL2023 defaults
  # to 2). cloud-init also drops 169.254.0.0/16 from containers as a second layer.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/scripts/cloud-init.yml", {
    data_volume_id = aws_ebs_volume.data.id
  })
  user_data_replace_on_change = true

  tags = {
    Name = local.name
  }

  lifecycle {
    # Pick up new AL2023 releases by replacing the instance on purpose (`-replace`), not on every plan
    ignore_changes = [ami]
  }

  # cloud-init installs Docker on first boot, so the host needs its NAT route before it starts
  depends_on = [aws_route.private_default, aws_route_table_association.this]
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  instance_id = aws_instance.host.id
  volume_id   = aws_ebs_volume.data.id

  stop_instance_before_detaching = true
}

## Outputs

output "instance_id" {
  value = aws_instance.host.id
}

output "secret_name" {
  value = aws_secretsmanager_secret.jarvis.name
}

output "nat_public_ip" {
  description = "Static egress IP for Slack token IP restrictions and vendor allowlists"
  value       = aws_eip.nat.public_ip
}

output "ssm_session_command" {
  value = "aws ssm start-session --region ${data.aws_region.current.region} --target ${aws_instance.host.id}"
}
