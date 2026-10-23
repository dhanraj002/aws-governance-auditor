"""Versioned inventory contract shared by the collector and offline fixtures."""
import re

KINDS = ("security-group", "volume")
REQUIRED_TAGS = ("Owner", "Environment", "CostCentre")


def validate_regions(regions):
    if not regions or len(regions) != len(set(regions)):
        raise ValueError("Specify one or more unique AWS regions")
    if any(not isinstance(r, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", r) for r in regions):
        raise ValueError("Invalid AWS region format")


def validate_resource(resource, regions):
    kind = resource.get('kind')
    prefix = {'security-group':'sg', 'volume':'vol'}.get(kind)
    if not prefix or resource.get('region') not in regions:
        raise ValueError('Unknown resource kind or region')
    if not re.fullmatch(prefix + r'-[a-f0-9]+', resource.get('id', '')):
        raise ValueError('Invalid resource identifier')
    data = resource.get('data', {})
    tags = data.get('tags')
    if not isinstance(tags, dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in tags.items()):
        raise ValueError('Resource tags must be a string map')
    if kind == 'volume':
        if not isinstance(data.get('encrypted'), bool):
            raise ValueError('Unknown volume encryption state')
        if data.get('state') not in {'creating','available','in-use','deleting','deleted','error'}:
            raise ValueError('Unknown volume lifecycle state')
        if not isinstance(data.get('attachments'), list) or not isinstance(data.get('size_gib'), int) or data['size_gib'] < 1:
            raise ValueError('Invalid volume size or attachments')
    else:
        if not isinstance(data.get('ingress'), list):
            raise ValueError('Missing security group ingress')
        for rule in data['ingress']:
            if not isinstance(rule.get('IpProtocol'), str):
                raise ValueError('Missing ingress protocol')
            protocol = rule['IpProtocol']
            if protocol not in ('tcp','udp','icmp','icmpv6','-1') and not (protocol.isdigit() and 0 <= int(protocol) <= 255):
                raise ValueError('Unknown ingress protocol')
            if rule['IpProtocol'] in ('tcp','6'):
                if not all(isinstance(rule.get(k),int) for k in ('FromPort','ToPort')) or not 0 <= rule['FromPort'] <= rule['ToPort'] <= 65535:
                    raise ValueError('Invalid TCP port range')
            for key, field in [('IpRanges','CidrIp'), ('Ipv6Ranges','CidrIpv6')]:
                import ipaddress
                for entry in rule.get(key, []):
                    try:
                        network = ipaddress.ip_network(entry[field], strict=False)
                        if network.version != (4 if key == 'IpRanges' else 6):
                            raise ValueError('Wrong IP family')
                    except (KeyError, ValueError) as error:
                        raise ValueError('Invalid ingress CIDR') from error


def validate_snapshot(snapshot):
    if snapshot.get('schema_version') != 1 or snapshot.get('source') not in ('fixture','aws'):
        raise ValueError('Unsupported inventory schema or source')
    if not re.fullmatch(r'[0-9]{12}', snapshot.get('account_id', '')):
        raise ValueError('Invalid account identifier')
    regions = snapshot.get('regions', [])
    validate_regions(regions)
    expected = {(region,kind) for region in regions for kind in KINDS}
    scans = snapshot.get('scans', [])
    keys = [(s.get('region'), s.get('kind')) for s in scans]
    if set(keys) != expected or len(keys) != len(expected):
        raise ValueError('Coverage must include every requested region and resource kind exactly once')
    if any(s.get('status') not in ('complete','incomplete') for s in scans):
        raise ValueError('Unknown scan status')
    seen = set()
    for resource in snapshot.get('resources', []):
        validate_resource(resource, regions)
        key = (resource['region'], resource['kind'], resource['id'])
        if key in seen:
            raise ValueError('Duplicate resource in inventory')
        seen.add(key)
    # Counts make it harder to pass a truncated fixture off as a complete inventory.
    for scan in scans:
        actual = sum(1 for region,kind,_ in seen if (region,kind) == (scan['region'],scan['kind']))
        if scan.get('count') != actual:
            raise ValueError('Coverage count does not match inventory')
    return snapshot


def resource_arn(snapshot, resource):
    return f"arn:aws:ec2:{resource['region']}:{snapshot['account_id']}:{resource['kind']}/{resource['id']}"
