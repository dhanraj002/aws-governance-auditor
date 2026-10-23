import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from auditor.report import build_report, markdown


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only AWS governance audit. Offline snapshots require no credentials.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--snapshot', type=Path, help='Evaluate a saved inventory or synthetic fixture without AWS calls')
    source.add_argument('--live', action='store_true', help='Collect inventory with AWS Describe APIs')
    parser.add_argument('--regions', nargs='+', help='Explicit regions for live collection; no automatic all-region scan')
    parser.add_argument('--profile', help='Existing AWS SDK/SSO profile; never pass access keys')
    parser.add_argument('--exceptions', type=Path)
    parser.add_argument('--output', type=Path, required=True, help='Local report directory; contains AWS resource identifiers')
    parser.add_argument('--fail-on', choices=['low','medium','high'], default='medium')
    args = parser.parse_args(argv)
    if args.live and not args.regions:
        parser.error('--live requires --regions')
    if args.snapshot and (args.regions or args.profile):
        parser.error('--regions and --profile apply only to --live')
    try:
        if args.snapshot:
            snapshot = json.loads(args.snapshot.read_text())
        else:
            try:
                import boto3
                from auditor.collect import collect
            except ImportError:
                raise ValueError('Live mode requires installation with pip install ".[aws]"') from None
            snapshot = collect(boto3.Session(profile_name=args.profile), args.regions)
        exceptions = json.loads(args.exceptions.read_text()) if args.exceptions else {'exceptions':[]}
        report = build_report(snapshot, exceptions, datetime.now(timezone.utc), args.fail_on)
        # Files are private by default even when the shell's umask is permissive.
        args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        payloads = {'report.json':json.dumps(report,indent=2)+'\n', 'report.md':markdown(report)}
        for name,content in payloads.items():
            path=args.output/name
            # Refuse symlinks to avoid overwriting an unrelated file.
            import os
            fd=os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd,'w') as dest:
                os.fchmod(dest.fileno(), 0o600)
                dest.write(content)
        print(f"Wrote reports to {args.output}; findings={len(report['findings'])}; complete={report['complete']}")
        return report['exit_code']
    except Exception as error:
        # Do not print SDK credential errors or response bodies containing account context.
        if isinstance(error, (ValueError, OSError, KeyError, TypeError)):
            print(f'Audit could not finish ({type(error).__name__}): check input files, schema and output permissions.',file=sys.stderr)
        else:
            print(f'Audit could not finish ({type(error).__name__}); check AWS profile, permissions and connectivity.',file=sys.stderr)
        return 2
