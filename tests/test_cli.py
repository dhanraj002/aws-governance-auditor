import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from auditor.cli import main

FIXTURE=Path(__file__).resolve().parents[1]/'examples/inventory.json'

class CliTests(unittest.TestCase):
    def test_offline_report_never_constructs_aws_session(self):
        with tempfile.TemporaryDirectory() as directory, patch('boto3.Session') as session, contextlib.redirect_stdout(io.StringIO()):
            result=main(['--snapshot',str(FIXTURE),'--output',directory])
            self.assertEqual(result,1)
            session.assert_not_called()
            report=json.loads((Path(directory)/'report.json').read_text())
            self.assertEqual(report['source'],'fixture')
            self.assertEqual(len(report['findings']),4)
            self.assertEqual((Path(directory)/'report.json').stat().st_mode & 0o777,0o600)

    def test_malformed_inventory_returns_error_not_clean(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            bad=Path(directory)/'bad.json';bad.write_text('{}')
            self.assertEqual(main(['--snapshot',str(bad),'--output',directory]),2)

    def test_incomplete_inventory_returns_two(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            data=json.loads(FIXTURE.read_text());data['scans'][0]['status']='incomplete'
            path=Path(directory)/'partial.json';path.write_text(json.dumps(data))
            self.assertEqual(main(['--snapshot',str(path),'--output',directory]),2)

    def test_live_requires_explicit_regions(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(['--live','--output','reports'])
        self.assertEqual(error.exception.code,2)

    def test_report_symlink_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root=Path(directory);target=root/'keep.txt';target.write_text('keep')
            (root/'report.json').symlink_to(target)
            self.assertEqual(main(['--snapshot',str(FIXTURE),'--output',directory]),2)
            self.assertEqual(target.read_text(),'keep')
