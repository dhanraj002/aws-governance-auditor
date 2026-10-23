# Validation

23 October 2026 build. Local checks are recorded below; GitHub CI runs the same checks on Linux.

The sample inventory and report are synthetic. AWS SDK tests use botocore Stubber and fixed placeholder credentials; they make no live AWS requests. Terraform tests use a mock provider. Live-account permissions, inventory volume and operational findings remain unverified.

Local Python regression suite: **31 passed** using Python 3.14.7 and boto3/botocore 1.43.118. Coverage includes paginated SDK collection, a denied second page, deduplication, region isolation, incomplete coverage, UTC exception boundaries and CLI output behavior.

Offline demonstration: **4 findings**, complete fixture coverage, expected exit code **1**. The generated Markdown and JSON are committed under examples. Dependency versions are recorded in requirements-aws.lock.

Terraform 1.16.1 configuration validation passed with AWS provider 6.70.0. **2 mocked policy tests passed.** They check the exact read-only actions, region condition and rejection of empty scope.
