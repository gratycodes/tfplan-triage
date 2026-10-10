module "ledger_db" {
  source    = "./modules/postgres"
  name      = "ledger"
  encrypted = false
}

resource "aws_s3_bucket" "statements" {
  bucket = "acme-statements-prod"
}

resource "aws_s3_bucket_public_access_block" "statements" {
  bucket                  = aws_s3_bucket.statements.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "scratch" {
  bucket        = "acme-scratch-prod"
  force_destroy = true
}

resource "aws_iam_role" "ci_deployer" {
  name = "ci-deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ci_deployer" {
  name = "deploy-statements"
  role = aws_iam_role.ci_deployer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::acme-statements-prod/*"
    }]
  })
}

resource "aws_security_group" "api" {
  name   = "api"
  vpc_id = "vpc-0a1b2c3d4e5f60789"
}

resource "aws_vpc_security_group_ingress_rule" "https_internal" {
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = "10.0.0.0/8"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_cloudwatch_log_group" "service" {
  for_each          = toset(["api", "ledger", "payouts", "refunds", "webhooks", "worker"])
  name              = "/acme/${each.key}"
  retention_in_days = 30
  tags              = { team = "payments" }
}
