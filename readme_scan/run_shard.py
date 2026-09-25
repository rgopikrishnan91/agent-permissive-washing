"""Execute one fixed corpus shard and export all evidence as text artifacts."""
from collections import Counter
from pathlib import Path
from importlib.metadata import version
import argparse
import base64
import hashlib
import io
import json
import platform
import subprocess
import sys
import tarfile
import time
from resource_limits import resources, choose_workers

HERE=Path(__file__).resolve().parent

def write(name,value):
    (HERE/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def validate():
    targets={t['id']:t for t in json.loads((HERE/'targets.json').read_text())}
    records={p.stem:json.loads(p.read_text()) for p in (HERE/'records').glob('*.json')}
    scans={p.stem:json.loads(p.read_text()) for p in (HERE/'scans').glob('*.json')}
    differences=[];digests=set();statuses=Counter();scanner_errors=[]
    if set(targets)!=set(records):differences.append('Target/record identifier sets differ')
    for key,record in records.items():
        target=targets.get(key)
        if not target:continue
        for field in ['id','arm','repo','target_commit','selected_licence','stratum']:
            if record[field]!=target[field]:differences.append(f'{key}: {field} differs')
        statuses[record['status']]+=1
        for item in record['files']+record['context_files']:
            if item['status']!='ok':continue
            path=HERE/'texts'/item['sha256']
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
                differences.append(f'{key}: missing or changed text {item["path"]}')
        digests.update(f['sha256'] for f in record['files'] if f['status']=='ok')
    if set(scans)!=digests:differences.append('Scan/text identifier sets differ')
    for key,scan in scans.items():
        if key!=scan['sha256']:differences.append(f'{key}: scan identifier differs')
        if scan['license_error'] or scan['holder_error']:scanner_errors.append(key)
    result=dict(integrity_passed=not differences,differences=differences,
        repositories=len(targets),recorded_repositories=len(records),statuses=dict(statuses),
        unique_readme_texts=len(digests),readable_readme_paths=sum(f['status']=='ok' for r in records.values() for f in r['files']),
        scanner_error_digests=scanner_errors,
        missing_pinned_commits=sum(not t['target_commit'] for t in targets.values()),
        collection_failures=[key for key,r in records.items() if r['status'] in {'error','timeout'}],
        note='Integrity verification is not a copyright ownership determination. Context comparisons and ownership review occur after collection.')
    write('verification.json',result)
    return result

def export(destination):
    destination.mkdir(parents=True,exist_ok=True)
    paths=[p for p in HERE.glob('*.json') if p.is_file()]
    for folder in ['records','scans','texts','trees']:
        paths.extend(p for p in (HERE/folder).glob('*') if p.is_file())
    # Raw README text is preserved for audit; no fetched repository code runs.
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for path in sorted(paths):archive.add(path,arcname=str(path.relative_to(HERE)),recursive=False)
    raw=buffer.getvalue();encoded=base64.b64encode(raw).decode()
    chunks=[]
    for index,start in enumerate(range(0,len(encoded),96_000)):
        name=f'evidence_{index:04d}.tar.gz.b64.part'
        content=encoded[start:start+96_000]
        (destination/name).write_text('\n'.join(content[i:i+80] for i in range(0,len(content),80))+'\n')
        chunks.append(name)
    manifest=dict(encoding='base64 concatenated in listed order; gzip tar archive',parts=chunks,
        archive_sha256=hashlib.sha256(raw).hexdigest(),archive_bytes=len(raw),
        files={str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)})
    (destination/'archive_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    for name in ['run.json','verification.json','resources.json','collection_run.json','scan_run.json']:
        if (HERE/name).exists():(destination/name).write_bytes((HERE/name).read_bytes())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--export',type=Path,required=True)
    args=parser.parse_args();started=time.perf_counter();stages=[];error=None;checked=None
    try:
        observed=resources();observed.update(choose_workers(observed))
        observed.update(python=sys.version,platform=platform.platform(),scancode_version=version('scancode-toolkit'))
        write('resources.json',observed)
        assert observed['scancode_version']=='32.5.0'
        for script,workers in [('collect.py',8),('scan.py',observed['scan_workers'])]:
            phase=time.perf_counter()
            subprocess.run([sys.executable,'-u','-B',str(HERE/script),'--workers',str(workers)],cwd=HERE,check=True)
            stages.append(dict(script=script,workers=workers,seconds=time.perf_counter()-phase))
            write('stages.json',stages)
        checked=validate()
        if not checked['integrity_passed']:raise RuntimeError('Evidence integrity verification failed')
        if checked['scanner_error_digests'] or checked['collection_failures']:
            error='Incomplete retrieval or scanner errors; preserve evidence for targeted retry'
    except Exception as ex:
        error=type(ex).__name__+': '+str(ex)
    finally:
        write('run.json',dict(status='partial' if error else 'complete',error=error,
            seconds=time.perf_counter()-started,stages=stages,verification=checked,
            scope='README-named files at recorded corpus commits, including nested paths. No source-code scanning.'))
        export(args.export)
    print(json.dumps(dict(status='partial' if error else 'complete',error=error,export=str(args.export))))
    if error:raise SystemExit(1)

if __name__=='__main__':main()
