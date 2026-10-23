mock_provider "aws" {}
run "only_read_inventory" {
  command = plan
  assert {
    condition     = toset(jsondecode(aws_iam_policy.auditor.policy).Statement[0].Action) == toset(["ec2:DescribeSecurityGroups", "ec2:DescribeVolumes"])
    error_message = "The audit policy must not gain mutation or data-reading permissions."
  }
  assert {
    condition     = toset(jsondecode(aws_iam_policy.auditor.policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"]) == toset(var.allowed_regions)
    error_message = "Inventory permissions must remain region-scoped."
  }
}
run "reject_empty_scope" {
  command = plan
  variables { allowed_regions = [] }
  expect_failures = [var.allowed_regions]
}
