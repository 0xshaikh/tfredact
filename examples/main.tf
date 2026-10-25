# main.tf - Production web + PostgreSQL platform.
# Intentionally mixes correctly-marked and unmarked-sensitive variables,
# for secret-scanner test coverage.

terraform {
  required_version = ">= 1.9"
  required_providers {
    aws    = { source = "hashicorp/aws",    version = "~> 5.70" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" { region = var.region }

resource "aws_db_parameter_group" "appdb" {
  name   = "appdb-prod-pg"
  family = "postgres16"
  parameter {
    name         = "log_statement"
    value        = "all"
    apply_method = "immediate"
  }
}

resource "aws_rds_instance" "appdb" {
  identifier           = "appdb-prod"
  engine               = "postgres"
  engine_version       = "16.4"
  instance_class       = "db.r6g.large"
  db_name              = "appdb"
  deletion_protection  = true
  master_username      = "appdb_admin"
  master_user_password = var.database_password
}

resource "aws_instance" "app_worker" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.medium"
  key_name      = "prod-deploy-key"
  password      = var.ssh_private_key
  tags          = { Name = "app-worker-01" }
}

variable "region" { type = string; default = "us-east-1" }
variable "database_password" {
  description = "PostgreSQL admin password"
  type        = string
}
variable "api_token" {
  description = "External API bearer token consumed by the worker"
  type        = string
}
variable "ssh_private_key" {
  description = "OpenSSH private key material for the worker instance"
  type        = string
}
variable "smtp_password" {
  description = "SMTP application password for transactional mail"
  type        = string
}
variable "webhook_token" {
  description = "Slack incoming webhook secret"
  type        = string
}
variable "api_secret" {
  description = "Secret half of an API key pair"
  type        = string
  sensitive   = true
}
variable "webhook_endpoint" {
  description = "Slack webhook endpoint URL"
  type        = string
  sensitive   = true
}

output "database_password" { value = var.database_password }
output "db_endpoint"       { value = aws_rds_instance.appdb.endpoint }
