# Operations runbook

## Before scanning

Use the correct existing AWS profile and an explicit region list. Review the optional policy with the account administrator. Creating or attaching IAM resources is separate from running this read-only tool. This project has not provisioned any policy in a live account.

Run the synthetic demo first. Exit 1 is intentional because the fixture includes findings. Inspect coverage, active findings and exceptions before using the live mode.

## Interpreting a run

1. Check the process exit code and the report timestamp/source. A fixture report is not live-account evidence.
2. Review coverage before findings. If any scan is incomplete, investigate permissions, endpoint/network access, throttling or expired SSO credentials and rerun.
3. For public SSH/RDP rules, establish actual attachments and reachability before planning a restriction. Avoid locking out administrators.
4. For unattached volumes, contact the owner and verify backup/retention needs. Do not delete because a finding exists.
5. For unencrypted volumes, plan an encrypted replacement and test restoration with the application team.
6. Review missing owner tags and expired exceptions. Record actions in the normal change system.

## CI integration

Offline CI runs without AWS credentials. The synthetic demonstration is expected to return 1 and CI asserts that result. Live scans are not scheduled and live reports are not uploaded as public artifacts.

To integrate in a private operational workflow, preserve exit codes: 1 means findings; 2 means incomplete/error. Do not use `|| true` to make both disappear. Keep inventory/report artifacts private. Choose a severity threshold deliberately; an exception may make exit 0 possible while findings remain visible.

## Output handling

Reports are written with mode 0600 and a new output directory uses 0700 on POSIX systems. The CLI rejects a report-file symlink. Use a directory you control; it does not secure an untrusted filesystem or validate every parent directory. Output files are replaced on a successful run, so use a new directory per run when retaining history.

If execution fails before report generation, an older report in a reused directory may still exist. Always use the current exit code and timestamp. A live report can contain resource ARNs and account identifiers even though the tool omits raw tag values and API error messages.

## Evidence still needed

A real-account validation should record requested regions, caller role (redacted), total observed resources, denied-scan behavior, sample finding verification and runtime. No live scan, realized savings, organization-wide compliance or vulnerability exploitation is claimed by this repository.
