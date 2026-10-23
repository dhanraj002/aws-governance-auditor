# Design decisions

## Preserve uncertainty

Every requested region has separate coverage records for security groups and volumes. A failed page leaves earlier observations in the report but marks the whole resource-kind scan incomplete. The overall exit code is 2 even when the observed resources have no findings. Authentication failures stop the run before inventory; no successful report is claimed.

AWS inventory is not a transactionally consistent snapshot. The collector deduplicates resource IDs within a region/type, keeping the latest observation. Resources can still change during collection. A later complete scan is needed before acting on stale findings.

## Keep collection and rules separate

Offline evaluation uses a versioned inventory contract and has no SDK dependency. Live mode normalizes only fields needed by rules. Reports include identifiers, missing tag keys and evidence, not arbitrary tag values, rule descriptions or raw SDK error messages. Live resource identifiers still reveal infrastructure context: keep reports private and never commit live output.

SDK retries are bounded (standard mode, four total attempts) with connect/read timeouts. Collection uses pagination rather than one Describe response. A page failure is recorded, then the other resource kinds and regions continue. There is no whole-run deadline; large accounts may take time proportional to inventory and retries.

## Narrow permissions and no remediation

The collector invokes only identity and Describe APIs. Terraform creates an unattached IAM managed policy with `aws:RequestedRegion` conditions. Describe APIs require `Resource: "*"`; this does not grant write access. GetCallerIdentity does not require an explicit allow in the policy. Other policies on the chosen identity may grant more permissions; use a dedicated read-only identity when operationally practical.

Unattached does not mean abandoned. A volume may be a recovery asset, temporarily detached or held under retention. The tool does not infer detachment age from CreateTime, estimate savings, create snapshots or delete volumes. Remediation requires owner review.

## Explain what a rule proves

A public administrative ingress rule is a configuration observation. Attached instances, network interfaces, routes, NACLs, host firewalls and authentication are outside this first version. An unused group can still trigger the rule. Prefix lists, referenced security groups, narrower public CIDRs and UDP administrative traffic are not evaluated. The rule focuses on globally open TCP SSH/RDP, including IPv6, all protocols and broad TCP ranges.

An unencrypted EBS volume requires a replacement/migration plan. The auditor does not read its contents or KMS keys. Tags express the project's ownership convention, not a universal AWS requirement. AWS-managed resources can have legitimate exceptions; use an explicit, dated exception rather than a blanket account-wide enforcement policy.

## Why no S3 or IAM-wide scanner yet

These need separate semantics. S3 public access depends on interacting account, bucket, access-point and organization controls; a single missing bucket setting does not prove exposure. Keeping this version to EC2/EBS makes each finding explainable and testable. Cross-account Organizations discovery and non-commercial AWS partitions are also out of scope.

## Sources

- [AWS SDK DescribeSecurityGroups paginator](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/paginator/DescribeSecurityGroups.html)
- [AWS SDK DescribeVolumes paginator](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/paginator/DescribeVolumes.html)
- [AWS STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [AWS S3 public-access control interactions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
