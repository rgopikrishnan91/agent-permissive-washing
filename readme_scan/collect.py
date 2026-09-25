"""Recover README files at immutable pilot commits; never execute repository code."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
from license_names import file_class
ENV={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'true','GIT_LFS_SKIP_SMUDGE':'1'}
README=re.compile(r'^readme(?:[._-].*)?$',re.I)
MAX_READMES=500
MAX_BYTES=1_000_000

def sha(data):return hashlib.sha256(data).hexdigest()
def gitblob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def command(args,cwd,timeout=120,inp=None):
    r=subprocess.run(args,cwd=cwd,env=ENV,input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if r.returncode:raise RuntimeError(r.stderr.decode('utf-8','replace')[-700:])
    return r.stdout

def collect(target):
    started=time.perf_counter()
    result=dict(id=target['id'],arm=target['arm'],repo=target['repo'],target_commit=target['target_commit'],
                selected_licence=target['selected_licence'],stratum=target['stratum'],files=[],context_files=[])
    try:
        commit=target['target_commit']
        if not commit:return dict(result,status='no_pinned_commit',seconds=time.perf_counter()-started)
        assert re.fullmatch(r'[0-9a-f]{40}',commit)
        assert re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',target['repo'])
        directory=HERE/'git'/target['id']
        directory.mkdir(parents=True,exist_ok=True)
        if not (directory/'config').exists():
            command(['git','init','--bare','--quiet'],directory)
            command(['git','remote','add','origin','https://github.com/'+target['repo']+'.git'],directory)
        network_started=time.perf_counter()
        command(['git','fetch','--depth=1','--filter=blob:none','--no-tags','--quiet','origin',commit],directory,180)
        resolved=command(['git','rev-parse','FETCH_HEAD^{commit}'],directory).decode().strip()
        assert resolved==commit
        raw_tree=command(['git','ls-tree','-r','-z',commit],directory,120)
        tree={}
        for entry in raw_tree.split(b'\0'):
            if not entry:continue
            metadata,path=entry.split(b'\t',1)
            mode,kind,blob=metadata.decode().split()
            if kind=='blob':tree[path.decode('utf-8','replace')]=(mode,blob)
        result['tree_blob_paths']=len(tree)
        candidates=sorted((p for p,(mode,_) in tree.items() if README.fullmatch(p.rsplit('/',1)[-1])),key=lambda p:(p.count('/'),p))
        selected=candidates[:MAX_READMES]
        result['readmes_discovered']=len(candidates)
        result['readme_cap_reached']=len(candidates)>MAX_READMES
        result['skipped_symlink_readmes']=[p for p in selected if tree[p][0]=='120000']
        selected=[p for p in selected if tree[p][0]!='120000']
        context=[p for p in tree if ('/' not in p and file_class(p) in {'license','notice'}) or p in {'.claude-plugin/plugin.json','.claude-plugin/marketplace.json'}] if target['arm']=='plugin' else []
        result['current_root_context_paths']=sorted(context)
        cached={}  # Cloud pilot fetches all README blobs; no local SQLite cache.
        wanted={tree[p][1] for p in selected+context}
        missing=sorted(wanted-set(cached))
        if missing:
            command(['git','-c','fetch.negotiationAlgorithm=noop','fetch','--quiet','--no-tags','--no-write-fetch-head','--recurse-submodules=no','--filter=blob:none','--stdin','origin'],directory,180,('\n'.join(missing)+'\n').encode())
            batch=command(['git','cat-file','--batch'],directory,180,('\n'.join(missing)+'\n').encode())
            pos=0
            while pos<len(batch):
                end=batch.index(b'\n',pos)
                header=batch[pos:end].decode().split();pos=end+1
                if len(header)!=3 or header[1]!='blob':raise RuntimeError('Missing requested blob')
                size=int(header[2]);data=batch[pos:pos+size];pos+=size+1
                assert len(data)==size and gitblob(data)==header[0]
                cached[header[0]]=data
        result['network_seconds']=time.perf_counter()-network_started
        result['cached_readme_blobs_reused']=sum(tree[p][1] not in missing for p in selected)
        result['fetched_blobs']=len(missing)
        for path in selected+context:
            data=cached[tree[path][1]]
            entry=dict(path=path,git_blob=tree[path][1],raw_sha256=sha(data),bytes=len(data),
                       status='binary' if b'\0' in data else 'oversize' if len(data)>MAX_BYTES else 'ok')
            if entry['status']=='ok':
                text=data.decode('utf-8','replace')
                entry['sha256']=sha(text.encode('utf-8'))
                cas=HERE/'texts'/entry['sha256']
                cas.write_text(text)
            result['files' if path in selected else 'context_files'].append(entry)
        if target['arm']=='plugin':
            current={f['path']:f['raw_sha256'] for f in result['context_files'] if f['status']=='ok'}
            result['baseline_root_context_unchanged']=current==target['baseline_root_context'] and len(current)==len(context)
        else:result['baseline_root_context_unchanged']=True
        with gzip.open(HERE/'trees'/(target['id']+'.json.gz'),'wt') as stream:
            json.dump(dict(commit=commit,files={p:dict(mode=m,git_blob=b) for p,(m,b) in tree.items()}),stream,sort_keys=True)
        result['status']='partial' if result['readme_cap_reached'] or result['skipped_symlink_readmes'] or any(f['status']!='ok' for f in result['files']) else 'ok'
    except subprocess.TimeoutExpired:
        result.update(status='timeout',error='Git operation exceeded its recorded timeout')
    except Exception as ex:
        result.update(status='error',error=str(ex)[:800])
    result['seconds']=time.perf_counter()-started
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--workers',type=int,default=8);parser.add_argument('--limit',type=int);args=parser.parse_args()
    for folder in ['git','texts','trees','records']:(HERE/folder).mkdir(exist_ok=True)
    targets=json.loads((HERE/'targets.json').read_text())
    todo=[t for t in targets if not (HERE/'records'/(t['id']+'.json')).exists()]
    if args.limit:todo=todo[:args.limit]
    started=time.perf_counter();done=0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(collect,t) for t in todo]):
            result=future.result();(HERE/'records'/(result['id']+'.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
            done+=1
            print(json.dumps(dict(done=done,total=len(todo),repo=result['repo'],arm=result['arm'],status=result['status'],readmes=len(result['files']),seconds=round(result['seconds'],2),elapsed=round(time.perf_counter()-started,1))),flush=True)
    (HERE/'collection_run.json').write_text(json.dumps(dict(workers=args.workers,attempted=len(todo),elapsed_seconds=time.perf_counter()-started),indent=2)+'\n')

if __name__=='__main__':main()
