"""Launch a fixed shard; preserve setup/runtime evidence in the repository diff."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import hashlib
import re
import tarfile
import shutil
import subprocess
import tempfile
import time

HERE=Path(__file__).resolve().parent

def now():return datetime.now(timezone.utc).isoformat()

def extract_seed(archive_path, work):
    """Extract only hash-addressed regular seed files, never links or traversal."""
    if not archive_path.exists():
        return dict(present=False, files=0)
    count=0
    with tarfile.open(archive_path, 'r:gz') as archive:
        seen=set()
        for member in archive:
            name=member.name
            if member.isdir() and name.rstrip('/') in {'seed_blobs','seed_scans'}:
                continue
            if not member.isfile() or not re.fullmatch(r'seed_blobs/[0-9a-f]{40}|seed_scans/[0-9a-f]{64}\.json',name):
                raise ValueError('Unsafe seed archive member: '+name)
            if name in seen:
                raise ValueError('Duplicate seed archive member: '+name)
            seen.add(name)
            if member.size>20_000_000:
                raise ValueError('Oversize seed archive member: '+name)
            data=archive.extractfile(member).read()
            if name.startswith('seed_blobs/'):
                digest=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
                if digest!=name.split('/')[1]:
                    raise ValueError('Seed Git blob hash mismatch: '+name)
            destination=work/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(data)
            count+=1
    return dict(present=True, files=count, archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--shard',type=int,required=True)
    args=parser.parse_args();assert 0<=args.shard<64
    out=HERE.parent/f'skill_cloud_shard_{args.shard:02d}';out.mkdir(exist_ok=True)
    timing=dict(shard=args.shard,started_at=now());started=time.perf_counter()
    try:
        work=Path(tempfile.mkdtemp(prefix=f'skill-readme-shard-{args.shard:02d}-'))
        for name in ['collect.py','scan.py','sc_best.py','common.py','rules.py','license_names.py',
                     'resource_limits.py','requirements-lock.txt','run_shard.py']:
            shutil.copy2(HERE/name,work/name)
        shutil.copy2(HERE/'shards'/f'{args.shard:02d}.json',work/'targets.json')
        (work/'shard.json').write_text(json.dumps(dict(shard=args.shard,total_shards=64)))
        seed=extract_seed(HERE/'inputs'/f'{args.shard:02d}.tar.gz',work)
        (work/'seed_input.json').write_text(json.dumps(seed,indent=2)+'\n')
        timing['seed_input']=seed
        python=shutil.which('python3.12')
        if not python:raise RuntimeError('Python 3.12 is unavailable; configure the environment runtime')
        venv=work/'.venv'
        subprocess.run([python,'-m','venv',str(venv)],check=True)
        with (out/'setup.log').open('w') as log:
            result=subprocess.run([str(venv/'bin/python'),'-m','pip','install','-r',str(work/'requirements-lock.txt')],stdout=log,stderr=subprocess.STDOUT)
        timing.update(setup_seconds=time.perf_counter()-started,setup_returncode=result.returncode)
        if result.returncode:raise RuntimeError('Dependency setup failed; see setup.log')
        timing['scan_pipeline_started_at']=now()
        (out/'task_timing.json').write_text(json.dumps(timing,indent=2)+'\n')
        result=subprocess.run([str(venv/'bin/python'),'-u','-B',str(work/'run_shard.py'),'--export',str(out)])
        timing['returncode']=result.returncode
        if result.returncode:raise RuntimeError('Shard incomplete; see exported run.json')
    except Exception as ex:
        timing['error']=type(ex).__name__+': '+str(ex)
        (out/'EXECUTION_FAILURE.txt').write_text(timing['error']+'\n')
        raise
    finally:
        timing.update(finished_at=now(),seconds=time.perf_counter()-started)
        (out/'task_timing.json').write_text(json.dumps(timing,indent=2)+'\n')

if __name__=='__main__':main()
