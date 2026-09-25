"""Integrity, seed reuse, retry, and compact transport regression tests."""
import base64
import hashlib
import io
import json
from pathlib import Path
import signal
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import launch
import run_shard
import scan


def digest(data):return hashlib.sha256(data).hexdigest()
def blob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def result(data):return dict(sha256=digest(data),bytes=len(data),matches=[],statements=[],license_error=None,holder_error=None,scancode_version='32.5.0')

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.patches=[patch.object(run_shard,'HERE',self.root),patch.object(scan,'HERE',self.root)]
        for p in self.patches:p.start()
        for folder in ['texts','records','scans','seed_scans']:(self.root/folder).mkdir()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def put(self,path,value):
        (self.root/path).write_text(json.dumps(value))
    def fixture(self):
        targets=[dict(id='one',arm='skill',repo='owner/repo',target_commit='a'*40,selected_licence='mixed',stratum='missing_holder',directories=['','skills/a'],skill_occurrences=2)]
        self.put('targets.json',targets)
        files=[]
        for path,data in [('README.md',b'No notice here'),('skills/a/README.md',b'Copyright 2024 Alice Example')]:
            d=digest(data);(self.root/'texts'/d).write_bytes(data)
            files.append(dict(path=path,git_blob=blob(data),raw_sha256=d,sha256=d,bytes=len(data),status='ok'))
            s=result(data)
            if 'skills/' in path:
                s['statements']=[dict(statement=data.decode(),start_line=1,end_line=1,detected_holders=['Alice Example'],holders=['alice example'],years=['2024'],copyright_marker=True,holder_and_year_present=True)]
            self.put('scans/'+d+'.json',s)
        record=dict(targets[0],status='ok',files=files,context_files=[],inventory_complete=True,retrieval_complete=True,resolved_commit='a'*40,readme_cap_reached=False)
        self.put('records/one.json',record)
        return record
    def test_scope_hash_and_scan_validation(self):
        record=self.fixture()
        self.assertTrue(run_shard.validate()['integrity_passed'])
        record['files'][0]['path']='other/README.md';self.put('records/one.json',record)
        self.assertFalse(run_shard.validate()['integrity_passed'])
        record['files'][0]['path']='README.md';record['files'][0]['git_blob']='b'*40;self.put('records/one.json',record)
        self.assertFalse(run_shard.validate()['integrity_passed'])
    def test_scope_variants_zero_occurrences_and_commit_checks(self):
        record=self.fixture();record['files'][0]['path']='READ_ME.md';record['skill_occurrences']=0
        self.put('records/one.json',record)
        targets=json.loads((self.root/'targets.json').read_text());targets[0]['skill_occurrences']=0;self.put('targets.json',targets)
        self.assertTrue(run_shard.validate()['integrity_passed'])
        record['resolved_commit']='b'*40;self.put('records/one.json',record)
        self.assertFalse(run_shard.validate()['integrity_passed'])
        record['resolved_commit']='a'*40;record['readme_cap_reached']=True;self.put('records/one.json',record)
        self.assertFalse(run_shard.validate()['integrity_passed'])
    def test_compact_export_preserves_records_scans_positive_text_and_verifies(self):
        record=self.fixture();self.assertTrue(run_shard.validate()['integrity_passed'])
        out=self.root/'out';run_shard.export(out)
        manifest=json.loads((out/'archive_manifest.json').read_text())
        raw=base64.b64decode(''.join((out/name).read_text() for name in manifest['parts']))
        self.assertEqual(digest(raw),manifest['archive_sha256'])
        extracted=self.root/'extracted';extracted.mkdir()
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive:
                data=archive.extractfile(member).read()
                self.assertEqual(digest(data),manifest['files'][member.name])
                p=extracted/member.name;p.parent.mkdir(exist_ok=True,parents=True);p.write_bytes(data)
        self.assertTrue((extracted/'records/one.json').exists())
        self.assertEqual(len(list((extracted/'scans').glob('*.json'))),2)
        self.assertEqual(len(list((extracted/'texts').glob('*'))),1)
        with patch.object(run_shard,'HERE',extracted):
            self.assertTrue(run_shard.validate(require_all_texts=False)['integrity_passed'])
            self.assertFalse(run_shard.validate(require_all_texts=True)['integrity_passed'])
    def test_reuse_rejects_error_version_and_hash_mismatch(self):
        inputs=[b'good',b'error',b'version',b'wronghash',b'missingstatus']
        for i,data in enumerate(inputs):
            d=digest(data);(self.root/'texts'/d).write_bytes(data);s=result(data)
            if i==1:s['license_error']='TimeoutError'
            if i==2:s['scancode_version']='32.4.0'
            if i==3:s['sha256']='0'*64
            if i==4:del s['holder_error']
            self.put('seed_scans/'+d+'.json',s)
        evidence=scan.reuse_scans([digest(data) for data in inputs])
        self.assertEqual(evidence['reused_seed_scans'],[digest(inputs[0])])
        self.assertEqual(len(evidence['rejected_cached_scans']),4)
        self.assertEqual(len(list((self.root/'scans').glob('*'))),1)
    def test_timeout_retries_only_timeout_and_records_attempts(self):
        attempts=[];calls=[]
        def operation():
            calls.append(True)
            if len(calls)==1:raise TimeoutError('first pass')
            return ['ok']
        with patch.object(signal,'alarm') as alarm:
            value,error=scan.stage_scan(operation,attempts)
        self.assertEqual(value,['ok']);self.assertIsNone(error)
        self.assertEqual([x['timeout_seconds'] for x in attempts],[30,120])
        self.assertIn('TimeoutError',attempts[0]['error']);self.assertIsNone(attempts[1]['error'])
        self.assertEqual([c.args[0] for c in alarm.call_args_list],[30,0,120,0])
        attempts=[]
        with patch.object(signal,'alarm'):
            _,error=scan.stage_scan(lambda:(_ for _ in ()).throw(ValueError('bad input')),attempts)
        self.assertEqual(len(attempts),1);self.assertIn('ValueError',error)
    def test_safe_seed_extract(self):
        data=b'readme';archive_path=self.root/'seed.tar.gz'
        def make(name,content=data,kind=None):
            with tarfile.open(archive_path,'w:gz') as archive:
                info=tarfile.TarInfo(name);info.size=len(content)
                if kind:info.type=kind
                archive.addfile(info,io.BytesIO(content))
        make('seed_blobs/'+blob(data))
        self.assertEqual(launch.extract_seed(archive_path,self.root/'work')['files'],1)
        for name,kind in [('../escape',None),('seed_blobs/'+'a'*40,None),('seed_blobs/'+'a'*40,tarfile.SYMTYPE)]:
            make(name,kind=kind)
            with self.assertRaises(ValueError):launch.extract_seed(archive_path,self.root/'bad')
    def test_real_notice_fixtures(self):
        scan.fixtures()
        checks=json.loads((self.root/'notice_parser_checks.json').read_text())
        self.assertTrue(all(c['passed'] for c in checks))

if __name__=='__main__':unittest.main()
