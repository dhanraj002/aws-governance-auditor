"""Only STS identity and EC2 Describe APIs; no resource mutations."""
from datetime import datetime, timezone
from auditor.model import KINDS, validate_regions, validate_resource, validate_snapshot


def normalize(kind, region, item):
    tags = {t['Key']: t['Value'] for t in item.get('Tags', [])}
    if kind == 'security-group':
        # Keep only fields needed by the rules, not rule descriptions or group names.
        ingress = []
        for permission in item['IpPermissions']:
            rule = {k:permission[k] for k in ('IpProtocol','FromPort','ToPort') if k in permission}
            rule['IpRanges'] = [{'CidrIp':x['CidrIp']} for x in permission.get('IpRanges', [])]
            rule['Ipv6Ranges'] = [{'CidrIpv6':x['CidrIpv6']} for x in permission.get('Ipv6Ranges', [])]
            ingress.append(rule)
        data = {'tags':tags, 'ingress':ingress}
        identifier = item['GroupId']
    else:
        data = {'tags':tags, 'encrypted':item['Encrypted'], 'state':item['State'],
                'attachments':[a.get('State','unknown') for a in item['Attachments']], 'size_gib':item['Size']}
        identifier = item['VolumeId']
    result = {'kind':kind, 'region':region, 'id':identifier, 'data':data}
    validate_resource(result, [region])
    return result


def collect(session, regions):
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
    validate_regions(regions)
    config = Config(retries={'mode':'standard', 'total_max_attempts':4}, connect_timeout=5, read_timeout=15)
    identity = session.client('sts', region_name=regions[0], config=config).get_caller_identity()
    if not identity['Arn'].startswith('arn:aws:'):
        raise ValueError('This release supports the commercial AWS partition only')
    snapshot = {'schema_version':1, 'source':'aws', 'account_id':identity['Account'],
                'collected_at':datetime.now(timezone.utc).isoformat(), 'regions':regions, 'resources':[], 'scans':[]}
    operations = {'security-group':('describe_security_groups','SecurityGroups'), 'volume':('describe_volumes','Volumes')}
    for region in regions:
        for kind in KINDS:
            scan = {'region':region, 'kind':kind, 'status':'complete', 'count':0}
            operation, key = operations[kind]
            collected = {}
            try:
                client = session.client('ec2', region_name=region, config=config)
                for page in client.get_paginator(operation).paginate(PaginationConfig={'PageSize':100}):
                    for item in page[key]:
                        resource = normalize(kind, region, item)
                        # A changing account may return duplicates across pages. Keep the latest observation.
                        collected[resource['id']] = resource
            except (BotoCoreError, ClientError, KeyError, ValueError) as error:
                scan['status'] = 'incomplete'
                # Error text may contain account context; retain only its stable code.
                scan['error_code'] = error.response['Error']['Code'] if isinstance(error, ClientError) else type(error).__name__
            snapshot['resources'].extend(collected.values())
            scan['count'] = len(collected)
            snapshot['scans'].append(scan)
    return validate_snapshot(snapshot)
