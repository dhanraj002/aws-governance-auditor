# Exception review

An exception is a tracked acceptance of one finding, not a removal of evidence. The finding remains in JSON and Markdown with status `excepted`, reviewer/owner, reason and expiry. At 00:00 UTC on the expiry date it becomes active again.

```json
{
  "exceptions": [
    {
      "rule": "SG_PUBLIC_ADMIN",
      "resource": "arn:aws:ec2:eu-central-1:123456789012:security-group/sg-00000000000000001",
      "owner": "platform-team",
      "reason": "Synthetic example only: short migration window; tracked in CHANGE-123.",
      "expires": "2026-11-01"
    }
  ]
}
```

Only an exact supported rule and exact resource ARN are accepted. Wildcards, duplicate rule/resource entries, blank owner/reason and invalid dates fail validation. Expired exceptions do not suppress findings. Exceptions that match no finding are listed for cleanup; they may be stale, or the resource may be in an incomplete scan.

In a team, store real exception files in a private repository, require an owning reviewer, reference a change/risk ticket, and keep expiry short. The CLI validates structure and expiry; it cannot verify that the named owner approved the exception. Anyone who controls the input file can change the accepted risks, so protect that file and use code review. Do not publish real account ARNs as a demonstration.
