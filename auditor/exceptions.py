"""Exact-resource, exact-rule exceptions with an exclusive UTC expiry date."""
import copy
from datetime import date
import re
from auditor.rules import RULES


def apply_exceptions(findings, document, today):
    if not isinstance(document, dict) or set(document) != {'exceptions'} or not isinstance(document['exceptions'], list):
        raise ValueError('Exception file must contain an exceptions list')
    records = {}
    for entry in document['exceptions']:
        if not isinstance(entry, dict) or set(entry) != {'rule','resource','owner','reason','expires'}:
            raise ValueError('Exception needs rule, resource, owner, reason and expires')
        if entry['rule'] not in RULES:
            raise ValueError('Unknown exception rule')
        if not isinstance(entry['resource'],str) or not re.fullmatch(r'arn:aws:ec2:[a-z0-9-]+:[0-9]{12}:(?:volume/vol|security-group/sg)-[a-f0-9]+',entry['resource']):
            raise ValueError('Exception must use an exact EC2 resource ARN; wildcards are not allowed')
        if any(not isinstance(entry[k],str) or not entry[k].strip() for k in ('owner','reason','expires')):
            raise ValueError('Exception owner, reason and expiry must be nonempty strings')
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}',entry['expires']):
            raise ValueError('Expiry must use YYYY-MM-DD')
        expiry = date.fromisoformat(entry['expires'])
        key = (entry['rule'], entry['resource'])
        if key in records:
            raise ValueError('Duplicate exception for a rule/resource pair')
        records[key] = (entry,expiry)
    results = copy.deepcopy(findings)
    matched = set()
    for finding in results:
        key = (finding['rule'],finding['resource'])
        if key in records:
            entry,expiry = records[key]
            matched.add(key)
            finding['exception'] = dict(entry)
            finding['status'] = 'excepted' if today < expiry else 'active'
            finding['exception_state'] = 'valid' if today < expiry else 'expired'
    notices = [{'rule':e['rule'],'resource':e['resource'],'state':'unmatched', 'expires':e['expires']}
               for key,(e,expiry) in records.items() if key not in matched]
    return results, notices
