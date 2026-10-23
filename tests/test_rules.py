import copy
from datetime import datetime, timezone, date, timedelta
import json
from pathlib import Path
import unittest
from auditor.rules import evaluate
from auditor.model import validate_snapshot
from auditor.report import build_report, markdown
from auditor.exceptions import apply_exceptions

FIXTURE = Path(__file__).resolve().parents[1] / 'examples/inventory.json'
EXCEPTIONS = Path(__file__).resolve().parents[1] / 'examples/exceptions.json'
NOW = datetime(2026,10,23,tzinfo=timezone.utc)

class RuleTests(unittest.TestCase):
    def setUp(self):
        self.inventory=json.loads(FIXTURE.read_text())

    def sg(self):
        return self.inventory['resources'][0]['data']

    def test_expected_findings(self):
        findings=evaluate(self.inventory)
        self.assertEqual(len(findings),4)
        self.assertEqual({f['rule'] for f in findings},{'SG_PUBLIC_ADMIN','EBS_UNENCRYPTED','EBS_UNATTACHED','MISSING_TAGS'})
        finding=next(f for f in findings if f['rule']=='SG_PUBLIC_ADMIN')
        self.assertEqual(finding['evidence']['sources'],[{'cidr':'0.0.0.0/0','port':22},{'cidr':'::/0','port':3389}])

    def test_port_range_includes_ssh_and_rdp(self):
        self.sg()['ingress']=[{'IpProtocol':'6','FromPort':0,'ToPort':4000,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]
        f=next(f for f in evaluate(self.inventory) if f['rule']=='SG_PUBLIC_ADMIN')
        self.assertEqual(len(f['evidence']['sources']),2)

    def test_all_protocols_needs_no_ports(self):
        self.sg()['ingress']=[{'IpProtocol':'-1','Ipv6Ranges':[{'CidrIpv6':'::/0'}]}]
        f=next(f for f in evaluate(self.inventory) if f['rule']=='SG_PUBLIC_ADMIN')
        self.assertEqual(len(f['evidence']['sources']),2)

    def test_private_or_non_admin_ports_do_not_trigger(self):
        for protocol,source,port in [('tcp','10.0.0.0/8',22),('udp','0.0.0.0/0',22),('tcp','0.0.0.0/0',443)]:
            with self.subTest(protocol=protocol,source=source,port=port):
                self.sg()['ingress']=[{'IpProtocol':protocol,'FromPort':port,'ToPort':port,'IpRanges':[{'CidrIp':source}]}]
                self.assertNotIn('SG_PUBLIC_ADMIN',{f['rule'] for f in evaluate(self.inventory)})

    def test_duplicate_ingress_does_not_duplicate_evidence(self):
        self.sg()['ingress']*=2
        f=next(f for f in evaluate(self.inventory) if f['rule']=='SG_PUBLIC_ADMIN')
        self.assertEqual(len(f['evidence']['sources']),2)

    def test_attached_or_transitioning_volume_is_not_cleanup_candidate(self):
        volume=self.inventory['resources'][1]['data']
        for state,attachments in [('in-use',['attached']),('creating',[]),('available',['detaching'])]:
            volume.update(state=state,attachments=attachments)
            self.assertNotIn('EBS_UNATTACHED',{f['rule'] for f in evaluate(self.inventory)})

    def test_whitespace_tag_is_missing(self):
        self.sg()['tags']['Owner']=' '
        f=next(f for f in evaluate(self.inventory) if f['rule']=='MISSING_TAGS' and '/sg-' in f['resource'])
        self.assertEqual(f['evidence']['missing_keys'],['Owner'])

    def test_unknown_encryption_is_rejected(self):
        self.inventory['resources'][1]['data']['encrypted']=None
        with self.assertRaises(ValueError):evaluate(self.inventory)

    def test_missing_scan_and_wrong_counts_are_rejected(self):
        for mutation in ['missing','count','duplicate']:
            with self.subTest(mutation=mutation):
                snapshot=copy.deepcopy(self.inventory)
                if mutation=='missing':snapshot['scans'].pop()
                elif mutation=='count':snapshot['scans'][0]['count']=0
                else:snapshot['resources'].append(snapshot['resources'][0])
                with self.assertRaises(ValueError):validate_snapshot(snapshot)

    def test_incomplete_coverage_takes_precedence_over_findings(self):
        self.inventory['scans'][1]['status']='incomplete'
        self.inventory['scans'][1]['error_code']='UnauthorizedOperation'
        report=build_report(self.inventory,{'exceptions':[]},NOW)
        self.assertEqual(report['exit_code'],2)
        self.assertIn('INCOMPLETE',markdown(report))

    def test_clean_empty_scope_is_success(self):
        self.inventory['resources']=[]
        for scan in self.inventory['scans']:scan['count']=0
        report=build_report(self.inventory,{'exceptions':[]},NOW)
        self.assertEqual(report['exit_code'],0)

    def test_input_not_mutated(self):
        before=copy.deepcopy(self.inventory)
        evaluate(self.inventory)
        self.assertEqual(before,self.inventory)

class ExceptionTests(unittest.TestCase):
    def setUp(self):
        self.findings=evaluate(json.loads(FIXTURE.read_text()))
        self.exceptions=json.loads(EXCEPTIONS.read_text())

    def test_exception_retained_and_expires_at_midnight(self):
        results,_=apply_exceptions(self.findings,self.exceptions,date(2026,10,31))
        self.assertEqual(next(f for f in results if f['rule']=='SG_PUBLIC_ADMIN')['status'],'excepted')
        self.assertEqual(next(f for f in self.findings if f['rule']=='SG_PUBLIC_ADMIN')['status'],'active')
        results,_=apply_exceptions(self.findings,self.exceptions,date(2026,11,1))
        self.assertEqual(next(f for f in results if f['rule']=='SG_PUBLIC_ADMIN')['status'],'active')
        self.assertEqual(next(f for f in results if f['rule']=='SG_PUBLIC_ADMIN')['exception_state'],'expired')

    def test_wildcard_and_missing_owner_and_duplicate_rejected(self):
        for mutation in ['wildcard','owner','duplicate','bad-date','unknown-rule']:
            with self.subTest(mutation=mutation):
                doc=copy.deepcopy(self.exceptions)
                if mutation=='wildcard':doc['exceptions'][0]['resource']='*'
                elif mutation=='owner':doc['exceptions'][0]['owner']=''
                elif mutation=='duplicate':doc['exceptions']*=2
                elif mutation=='unknown-rule':doc['exceptions'][0]['rule']='DISABLE_ALL'
                else:doc['exceptions'][0]['expires']='2026-99-99'
                with self.assertRaises(ValueError):apply_exceptions(self.findings,doc,NOW.date())

    def test_unmatched_exception_reported(self):
        results,notices=apply_exceptions([],self.exceptions,NOW.date())
        self.assertEqual(results,[])
        self.assertEqual(notices[0]['state'],'unmatched')

    def test_all_findings_excepted_can_pass_but_remain_visible(self):
        doc={'exceptions':[{'rule':f['rule'],'resource':f['resource'],'owner':'owner','reason':'Reviewed fixture', 'expires':'2026-11-01'} for f in self.findings]}
        report=build_report(json.loads(FIXTURE.read_text()),doc,NOW)
        self.assertEqual(report['exit_code'],0)
        self.assertEqual(len(report['findings']),4)

    def test_markdown_escapes_exception_content(self):
        self.exceptions['exceptions'][0]['reason']='<script>bad</script> | another\nline'
        report=build_report(json.loads(FIXTURE.read_text()),self.exceptions,NOW)
        result=markdown(report)
        self.assertNotIn('<script>',result)
        self.assertIn('&#124;',result)


class TimeBoundaryTests(unittest.TestCase):
    def test_expiry_uses_utc_not_local_date(self):
        now=datetime(2026,11,1,1,tzinfo=timezone(timedelta(hours=5,minutes=30)))
        report=build_report(json.loads(FIXTURE.read_text()),json.loads(EXCEPTIONS.read_text()),now)
        sg=next(f for f in report['findings'] if f['rule']=='SG_PUBLIC_ADMIN')
        self.assertEqual(sg['status'],'excepted')

    def test_naive_time_is_rejected(self):
        with self.assertRaises(ValueError):
            build_report(json.loads(FIXTURE.read_text()),{'exceptions':[]},datetime(2026,10,23))

    def test_unknown_protocol_is_rejected(self):
        inventory=json.loads(FIXTURE.read_text())
        inventory['resources'][0]['data']['ingress'][0]['IpProtocol']='unknown'
        with self.assertRaises(ValueError):evaluate(inventory)
