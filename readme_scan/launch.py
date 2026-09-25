"""Launch a fixed shard; preserve setup/runtime evidence in the repository diff."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import shutil
import subprocess
import tempfile
import time

HERE=Path(__file__).resolve().parent

def now():return datetime.now(timezone.utc).isoformat()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--shard',type=int,required=True)
    args=parser.parse_args();assert 0<=args.shard<64
    out=HERE.parent/f'codex_cloud_shard_{args.shard:02d}';out.mkdir(exist_ok=True)
    timing=dict(shard=args.shard,started_at=now());started=time.perf_counter()
    try:
        work=Path(tempfile.mkdtemp(prefix=f'readme-shard-{args.shard:02d}-'))
        for name in ['collect.py','scan.py','sc_best.py','common.py','rules.py','license_names.py',
                     'resource_limits.py','requirements-lock.txt','run_shard.py']:
            shutil.copy2(HERE/name,work/name)
        shutil.copy2(HERE/'shards'/f'{args.shard:02d}.json',work/'targets.json')
        (work/'shard.json').write_text(json.dumps(dict(shard=args.shard,total_shards=64)))
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
