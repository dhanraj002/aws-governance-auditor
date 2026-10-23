"""Small evidence-based rules; no automatic remediation or compliance claims."""
import ipaddress
from auditor.model import REQUIRED_TAGS, resource_arn, validate_snapshot

RULES = {'SG_PUBLIC_ADMIN', 'EBS_UNENCRYPTED', 'EBS_UNATTACHED', 'MISSING_TAGS'}
SEVERITY = {'low':0, 'medium':1, 'high':2}


def evaluate(snapshot):
    validate_snapshot(snapshot)
    findings = []
    def add(resource, rule, severity, summary, evidence, action):
        arn = resource_arn(snapshot, resource)
        findings.append({'id':f'{rule}:{arn}', 'rule':rule, 'severity':severity, 'resource':arn,
                         'region':resource['region'], 'summary':summary, 'evidence':evidence,
                         'recommended_action':action, 'status':'active'})
    for resource in snapshot['resources']:
        data = resource['data']
        missing = [k for k in REQUIRED_TAGS if not data['tags'].get(k, '').strip()]
        if missing:
            add(resource, 'MISSING_TAGS', 'medium', 'Ownership metadata is incomplete',
                {'missing_keys':missing}, 'Identify the owning team before changing or retiring this resource.')
        if resource['kind'] == 'volume':
            if not data['encrypted']:
                add(resource, 'EBS_UNENCRYPTED', 'high', 'Volume is not encrypted',
                    {'encrypted':False}, 'Plan an encrypted snapshot/copy and replacement with application-owner approval; encryption is not an in-place toggle.')
            if data['state'] == 'available' and not data['attachments']:
                add(resource, 'EBS_UNATTACHED', 'medium', 'Unattached volume needs an ownership review',
                    {'state':'available', 'size_gib':data['size_gib']},
                    'Check retention, recovery and owner requirements. No deletion or savings estimate is implied.')
        else:
            exposure = set()
            for rule in data['ingress']:
                protocol = rule['IpProtocol']
                if protocol not in ('tcp','6','-1'):
                    continue
                ports = [p for p in (22,3389) if protocol == '-1' or rule['FromPort'] <= p <= rule['ToPort']]
                for key,field in [('IpRanges','CidrIp'),('Ipv6Ranges','CidrIpv6')]:
                    for source in rule.get(key, []):
                        network = ipaddress.ip_network(source[field], strict=False)
                        if network.prefixlen == 0:
                            exposure.update((str(network), port) for port in ports)
            if exposure:
                add(resource, 'SG_PUBLIC_ADMIN', 'high', 'Ingress permits administrative TCP ports from any address',
                    {'sources':[{'cidr':cidr,'port':port} for cidr,port in sorted(exposure)]},
                    'Review group attachments, routes and host controls; prefer Session Manager or approved source ranges. This rule alone does not prove internet reachability.')
    return sorted(findings, key=lambda f:(-SEVERITY[f['severity']],f['id']))
