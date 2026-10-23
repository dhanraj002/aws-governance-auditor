# AWS governance audit

Source: **fixture** · Generated: 2026-10-23T12:12:05.727389+00:00

Coverage: **complete for requested scope**

Account: `123456789012` · Regions: eu-central-1

| Region | Resource kind | Status | Count | Error |
|---|---|---|---:|---|
| eu-central-1 | security-group | complete | 1 |  |
| eu-central-1 | volume | complete | 2 |  |

## Findings

| Severity | Rule | Resource | Status |
|---|---|---|---|
| high | EBS_UNENCRYPTED | arn:aws:ec2:eu-central-1:123456789012:volume/vol-00000000000000001 | active |
| high | SG_PUBLIC_ADMIN | arn:aws:ec2:eu-central-1:123456789012:security-group/sg-00000000000000001 | active |
| medium | EBS_UNATTACHED | arn:aws:ec2:eu-central-1:123456789012:volume/vol-00000000000000001 | active |
| medium | MISSING_TAGS | arn:aws:ec2:eu-central-1:123456789012:volume/vol-00000000000000001 | active |

### EBS_UNENCRYPTED — arn:aws:ec2:eu-central-1:123456789012:volume/vol-00000000000000001

Volume is not encrypted

Evidence: {&quot;encrypted&quot;: false}

Plan an encrypted snapshot/copy and replacement with application-owner approval; encryption is not an in-place toggle.

### SG_PUBLIC_ADMIN — arn:aws:ec2:eu-central-1:123456789012:security-group/sg-00000000000000001

Ingress permits administrative TCP ports from any address

Evidence: {&quot;sources&quot;: [{&quot;cidr&quot;: &quot;0.0.0.0/0&quot;, &quot;port&quot;: 22}, {&quot;cidr&quot;: &quot;::/0&quot;, &quot;port&quot;: 3389}]}

Review group attachments, routes and host controls; prefer Session Manager or approved source ranges. This rule alone does not prove internet reachability.

### EBS_UNATTACHED — arn:aws:ec2:eu-central-1:123456789012:volume/vol-00000000000000001

Unattached volume needs an ownership review

Evidence: {&quot;size_gib&quot;: 80, &quot;state&quot;: &quot;available&quot;}

Check retention, recovery and owner requirements. No deletion or savings estimate is implied.

### MISSING_TAGS — arn:aws:ec2:eu-central-1:123456789012:volume/vol-00000000000000001

Ownership metadata is incomplete

Evidence: {&quot;missing_keys&quot;: [&quot;Owner&quot;, &quot;CostCentre&quot;]}

Identify the owning team before changing or retiring this resource.

Exit code: **1**. Threshold: **medium**.

Read-only observations, not a compliance certification, verified exploit, deletion approval, or cost-savings claim.
