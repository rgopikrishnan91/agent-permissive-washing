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
import re
import subprocess
import sys
import tarfile
import time
from resource_limits import resources, choose_workers

HERE=Path(__file__).resolve().parent

def write(name,value):
    (HERE/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def validate(require_all_texts=True):
    target_list=json.loads((HERE/'targets.json').read_text())
    targets={t['id']:t for t in target_list}
    records={p.stem:json.loads(p.read_text()) for p in (HERE/'records').glob('*.json')}
    scans={p.stem:json.loads(p.read_text()) for p in (HERE/'scans').glob('*.json')}
    differences=[];digests=set();statuses=Counter();scanner_errors=[];text_sizes={}
    transport=json.loads((HERE/'transport.json').read_text()) if (HERE/'transport.json').exists() else {}
    allowed_omissions=set(transport.get('omitted_text_digests',[])) if not require_all_texts else set()
    if len(targets)!=len(target_list):differences.append('Duplicate target identifiers')
    if set(targets)!=set(records):differences.append('Target/record identifier sets differ')
    for key,record in records.items():
        target=targets.get(key)
        if not target:continue
        for field in ['id','arm','repo','target_commit','selected_licence','stratum','directories','skill_occurrences']:
            if record.get(field)!=target.get(field):differences.append(f'{key}: {field} differs')
        if target.get('arm')!='skill' or target.get('stratum')!='missing_holder':
            differences.append(f'{key}: wrong cohort')
        directories=target.get('directories',[])
        if not isinstance(directories,list) or not directories or any(
            not isinstance(d,str) or d.startswith('/') or '..' in d.split('/') or d.endswith('/') for d in directories):
            differences.append(f'{key}: invalid governing directories')
            directories=[]
        if not isinstance(target.get('skill_occurrences'),int) or target['skill_occurrences']<0:
            differences.append(f'{key}: invalid occurrence count')
        if record.get('inventory_complete') and record.get('resolved_commit')!=target['target_commit']:
            differences.append(f'{key}: inventory commit differs')
        if record.get('readme_cap_reached'):
            differences.append(f'{key}: unexpected README inventory cap')
        if record.get('status')=='ok' and not (record.get('inventory_complete') and record.get('retrieval_complete')):
            differences.append(f'{key}: complete status lacks complete inventory/retrieval')
        statuses[record['status']]+=1
        paths=[item['path'] for item in record['files']]
        if len(paths)!=len(set(paths)):differences.append(f'{key}: duplicate README paths')
        if record.get('context_files'):differences.append(f'{key}: unexpected context files')
        for item in record['files']:
            file_path=item['path'];parent,_,name=file_path.rpartition('/')
            if parent not in directories or not re.fullmatch(r'read[ _-]?me(?:[._-].*)?',name,re.I):
                differences.append(f'{key}: README outside governing directory scope: {file_path}')
            if not re.fullmatch('[0-9a-f]{40}',item.get('git_blob','')):
                differences.append(f'{key}: invalid Git blob identifier: {file_path}')
            if item['status']!='ok':continue
            digest=item.get('sha256','')
            if not re.fullmatch('[0-9a-f]{64}',digest) or not re.fullmatch('[0-9a-f]{64}',item.get('raw_sha256','')):
                differences.append(f'{key}: invalid text digest: {file_path}')
                continue
            digests.add(digest)
            path=HERE/'texts'/digest
            if not path.exists() and digest in allowed_omissions:continue
            if not path.exists():
                differences.append(f'{key}: missing text {file_path}')
                continue
            data=path.read_bytes();text_sizes[digest]=len(data)
            if hashlib.sha256(data).hexdigest()!=digest:
                differences.append(f'{key}: changed text {file_path}')
            if item['raw_sha256']==digest:
                blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
                if blob!=item['git_blob'] or len(data)!=item['bytes']:
                    differences.append(f'{key}: raw/Git blob mismatch {file_path}')
            elif not item.get('raw_blob_verified'):
                differences.append(f'{key}: normalized text lacks verified raw blob {file_path}')
    if set(scans)!=digests:differences.append('Scan/text identifier sets differ')
    for key,scan in scans.items():
        if key!=scan.get('sha256'):differences.append(f'{key}: scan identifier differs')
        if scan.get('scancode_version')!='32.5.0':differences.append(f'{key}: scanner version differs')
        if key in text_sizes and scan.get('bytes')!=text_sizes[key]:differences.append(f'{key}: scanner byte count differs')
        if 'license_error' not in scan or 'holder_error' not in scan:
            differences.append(f'{key}: scanner status is missing')
        if scan.get('license_error') or scan.get('holder_error'):scanner_errors.append(key)
    partial=[key for key,r in records.items() if r['status']!='ok']
    result=dict(integrity_passed=not differences,differences=differences,
        collection_targets=len(targets),recorded_collection_targets=len(records),
        repositories=len({t['repo'] for t in targets.values()}),
        recorded_repositories=len({r['repo'] for r in records.values()}),statuses=dict(statuses),
        skill_occurrences=sum(t['skill_occurrences'] for t in targets.values()),
        governing_directories=sum(len(t['directories']) for t in targets.values()),
        unique_readme_texts=len(digests),readable_readme_paths=sum(f['status']=='ok' for r in records.values() for f in r['files']),
        scanner_error_digests=scanner_errors,
        missing_pinned_commits=sum(not t['target_commit'] for t in targets.values()),
        collection_failures=partial,
        transported_texts_only=not require_all_texts,omitted_text_digests=len(allowed_omissions),
        note='Integrity verification is not a copyright ownership determination. Directory applicability and ownership review occur after collection.')
    write('verification.json' if require_all_texts else 'local_verification.json',result)
    return result

def export(destination):
    destination.mkdir(parents=True,exist_ok=True)
    # Codex rejected a full raw-text/tree export with diff_too_large. Preserve
    # every record and scan; return source text for positives and scanner errors.
    # Other pinned blobs remain recoverable by recorded commit and Git/SHA.
    selected=set()
    for path in (HERE/'scans').glob('*.json'):
        scan=json.loads(path.read_text())
        if scan.get('statements') or scan.get('license_error') or scan.get('holder_error') or any(match['is_text'] for match in scan.get('matches',[])):selected.add(scan['sha256'])
    for path in (HERE/'records').glob('*.json'):
        record=json.loads(path.read_text())
        if not record.get('baseline_root_context_unchanged'):
            selected.update(item['sha256'] for item in record.get('context_files',[]) if item['status']=='ok')
    all_texts={p.name for p in (HERE/'texts').glob('*') if p.is_file()}
    write('transport.json',dict(mode='compact skill evidence export v3',
        included_text_digests=sorted(selected & all_texts),omitted_text_digests=sorted(all_texts-selected),
        omitted_tree_archives=len(list((HERE/'trees').glob('*.json.gz'))),
        note='All README paths and all ScanCode results are retained. Full input text hashes were verified in the cloud before export. '
             'Positive findings and scanner-error texts are included; other raw texts/tree inventories are omitted from transport only. '
             'Recover any omitted input from its immutable commit and recorded blob hash when needed.'))
    paths=[p for p in HERE.glob('*.json') if p.is_file()]
    for folder in ['records','scans']:
        paths.extend(p for p in (HERE/folder).glob('*') if p.is_file())
    paths.extend(HERE/'texts'/digest for digest in sorted(selected & all_texts))
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
            scope='README documents in missing-holder Skill directories and their governing ancestors at original corpus commits. No ordinary source-code scanning.'))
        export(args.export)
    print(json.dumps(dict(status='partial' if error else 'complete',error=error,export=str(args.export))))
    if error:raise SystemExit(1)

if __name__=='__main__':main()
