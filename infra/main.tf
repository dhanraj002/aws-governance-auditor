terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
variable "region" { default = "eu-central-1" }
variable "allowed_regions" {
  type    = list(string)
  default = ["eu-central-1", "eu-west-1"]
  validation {
    condition     = length(var.allowed_regions) > 0 && alltrue([for r in var.allowed_regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", r))])
    error_message = "Use explicit AWS region names."
  }
}
provider "aws" { region = var.region }
resource "aws_iam_policy" "auditor" {
  name        = "portfolio-governance-auditor"
  description = "Read-only EC2 and EBS inventory in explicit regions. No credentials or object data access."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ReadInventory"
      Effect    = "Allow"
      Action    = ["ec2:DescribeSecurityGroups", "ec2:DescribeVolumes"]
      Resource  = "*"
      Condition = { StringEquals = { "aws:RequestedRegion" = var.allowed_regions } }
    }]
  })
  tags = { Owner = "dhanraj002", Environment = "lab", Project = "aws-governance-auditor", CostCentre = "portfolio" }
}
output "policy_arn" { value = aws_iam_policy.auditor.arn }
