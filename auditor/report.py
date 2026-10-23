"""Reports preserve active and excepted findings and failed scan coverage."""
from datetime import timezone
import html
import json
from auditor.exceptions import apply_exceptions
from auditor.rules import evaluate, SEVERITY


def build_report(snapshot, exceptions, now, fail_on='medium'):
    if now.tzinfo is None:
        raise ValueError('Report time must be timezone-aware')
    now = now.astimezone(timezone.utc)
    findings, notices = apply_exceptions(evaluate(snapshot), exceptions, now.date())
    incomplete = any(s['status'] != 'complete' for s in snapshot['scans'])
    failing = any(f['status'] == 'active' and SEVERITY[f['severity']] >= SEVERITY[fail_on] for f in findings)
    return {'schema_version':1, 'generated_at':now.isoformat(), 'source':snapshot['source'],
            'account_id':snapshot['account_id'], 'regions':snapshot['regions'],
            'coverage':snapshot['scans'], 'complete':not incomplete, 'findings':findings,
            'exception_notices':notices, 'fail_on':fail_on,
            'exit_code':2 if incomplete else (1 if failing else 0)}


def cell(value):
    return html.escape(str(value)).replace('|', '&#124;').replace('\n', ' ').replace('\r',' ')


def markdown(report):
    lines = ['# AWS governance audit', '', f"Source: **{report['source']}** · Generated: {cell(report['generated_at'])}", '',
             f"Coverage: **{'complete for requested scope' if report['complete'] else 'INCOMPLETE — do not interpret as a clean scan'}**", '',
             f"Account: `{report['account_id']}` · Regions: {', '.join(report['regions'])}", '',
             '| Region | Resource kind | Status | Count | Error |', '|---|---|---|---:|---|']
    for scan in report['coverage']:
        lines.append('| ' + ' | '.join(cell(scan.get(k,'')) for k in ('region','kind','status','count','error_code')) + ' |')
    lines += ['', '## Findings', '', '| Severity | Rule | Resource | Status |', '|---|---|---|---|']
    for f in report['findings']:
        lines.append('| ' + ' | '.join(cell(f[k]) for k in ('severity','rule','resource','status')) + ' |')
    if not report['findings']:
        lines += ['', 'No findings in the observed inventory. Check coverage above before interpreting this result.']
    for f in report['findings']:
        lines += ['', f"### {f['rule']} — {cell(f['resource'])}", '', cell(f['summary']), '',
                  f"Evidence: {cell(json.dumps(f['evidence'],sort_keys=True))}", '', cell(f['recommended_action'])]
        if 'exception' in f:
            e=f['exception']
            lines += ['', f"Exception ({f['exception_state']}): {cell(e['owner'])}; expires {e['expires']} at 00:00 UTC. {cell(e['reason'])}"]
    if report['exception_notices']:
        lines += ['', '## Unmatched exceptions', '']
        lines += [f"- {cell(e['rule'])}: {cell(e['resource'])} (expires {e['expires']})" for e in report['exception_notices']]
    lines += ['', f"Exit code: **{report['exit_code']}**. Threshold: **{report['fail_on']}**.", '',
              'Read-only observations, not a compliance certification, verified exploit, deletion approval, or cost-savings claim.', '']
    return '\n'.join(lines)
