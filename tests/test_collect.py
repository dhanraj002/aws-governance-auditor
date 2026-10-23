import unittest
from unittest.mock import Mock
import boto3
from botocore.stub import Stubber
from auditor.collect import collect

class CollectorTests(unittest.TestCase):
    def setUp(self):
        session=boto3.Session(aws_access_key_id='testing',aws_secret_access_key='testing',region_name='eu-central-1')
        self.sts=session.client('sts')
        self.ec2=session.client('ec2')
        self.sts_stub=Stubber(self.sts)
        self.ec2_stub=Stubber(self.ec2)
        self.sts_stub.add_response('get_caller_identity',{'Account':'123456789012','Arn':'arn:aws:iam::123456789012:user/test','UserId':'test'})
        self.sts_stub.activate()
        self.ec2_stub.activate()
        self.addCleanup(self.sts_stub.deactivate)
        self.addCleanup(self.ec2_stub.deactivate)
        self.session=Mock()
        self.session.client.side_effect=lambda service,**kwargs:self.sts if service=='sts' else self.ec2

    def group(self,identifier):
        return {'GroupId':identifier,'IpPermissions':[],'Tags':[]}

    def test_pagination_consumes_all_pages(self):
        self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[self.group('sg-01')],'NextToken':'next'}, {'MaxResults':100})
        self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[self.group('sg-02')]}, {'MaxResults':100,'NextToken':'next'})
        self.ec2_stub.add_response('describe_volumes',{'Volumes':[]},{'MaxResults':100})
        result=collect(self.session,['eu-central-1'])
        self.assertEqual(len(result['resources']),2)
        self.assertEqual(result['scans'][0]['count'],2)
        self.ec2_stub.assert_no_pending_responses()

    def test_denied_second_page_retains_observations_and_marks_incomplete(self):
        self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[self.group('sg-01')],'NextToken':'next'},{'MaxResults':100})
        self.ec2_stub.add_client_error('describe_security_groups','UnauthorizedOperation','private error details',expected_params={'MaxResults':100,'NextToken':'next'})
        self.ec2_stub.add_response('describe_volumes',{'Volumes':[]},{'MaxResults':100})
        result=collect(self.session,['eu-central-1'])
        self.assertEqual(len(result['resources']),1)
        self.assertEqual(result['scans'][0]['status'],'incomplete')
        self.assertEqual(result['scans'][0]['error_code'],'UnauthorizedOperation')
        self.assertNotIn('private error details',str(result))
        self.assertEqual(result['scans'][1]['status'],'complete')

    def test_duplicate_pages_are_deduplicated(self):
        self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[self.group('sg-01')],'NextToken':'next'},{'MaxResults':100})
        self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[self.group('sg-01')]},{'MaxResults':100,'NextToken':'next'})
        self.ec2_stub.add_response('describe_volumes',{'Volumes':[]},{'MaxResults':100})
        result=collect(self.session,['eu-central-1'])
        self.assertEqual(result['scans'][0]['count'],1)

    def test_unknown_resource_field_marks_scan_incomplete(self):
        self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[]},{'MaxResults':100})
        self.ec2_stub.add_response('describe_volumes',{'Volumes':[{'VolumeId':'vol-01','State':'available','Attachments':[],'Size':20}]},{'MaxResults':100})
        result=collect(self.session,['eu-central-1'])
        self.assertEqual(result['scans'][1]['status'],'incomplete')
        self.assertEqual(result['scans'][1]['count'],0)

    def test_each_requested_region_is_scanned(self):
        for _ in range(2):
            self.ec2_stub.add_response('describe_security_groups',{'SecurityGroups':[]},{'MaxResults':100})
            self.ec2_stub.add_response('describe_volumes',{'Volumes':[]},{'MaxResults':100})
        result=collect(self.session,['eu-central-1','eu-west-1'])
        self.assertEqual(len(result['scans']),4)
        regions={c.kwargs['region_name'] for c in self.session.client.call_args_list if c.args==('ec2',)}
        self.assertEqual(regions,{'eu-central-1','eu-west-1'})

    def test_identity_failure_stops_before_inventory(self):
        from botocore.exceptions import NoCredentialsError
        self.session.client.side_effect=NoCredentialsError()
        with self.assertRaises(NoCredentialsError):collect(self.session,['eu-central-1'])
