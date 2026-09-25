"""README-only ScanCode pilot, including statement-level holder/year evidence."""
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import argparse
import json
import multiprocessing
import re
import signal
import sys
import time

HERE=Path(__file__).resolve().parent
from sc_best import canon_lengths,textlike
from common import spdx_primary
from rules import copyright_holders

INDEX=None
CANON=None
YEAR=re.compile(r'(?<!\d)(?:18|19|20)\d{2}(?!\d)')
MARKER=re.compile(r'(?i)copyright|©|\bcopr\.?|\(c\)')

def notice_scan(text):
    from cluecode.copyrights import detect_copyrights_from_lines
    detections=list(detect_copyrights_from_lines(list(enumerate(text.splitlines(),1)),
                    include_copyrights=True,include_holders=True,include_authors=False))
    holders=[d for d in detections if getattr(d,'holder',None)]
    statements=[]
    for d in detections:
        raw=getattr(d,'copyright',None)
        if not raw:continue
        # ScanCode removes email addresses and intervening years from holder spans;
        # requiring the entire cleaned holder string as a substring loses valid lists.
        matching=[h.holder for h in holders if h.start_line>=d.start_line and h.end_line<=d.end_line]
        accepted=sorted(copyright_holders(matching,text=raw))
        years=sorted(set(YEAR.findall(raw)))
        marked=bool(MARKER.search(raw))
        statements.append(dict(statement=raw,start_line=d.start_line,end_line=d.end_line,
            detected_holders=matching,holders=accepted,years=years,copyright_marker=marked,
            holder_and_year_present=bool(marked and accepted and years)))
    return statements

def timeout(signum,frame):raise TimeoutError('Stage exceeded 30 seconds')

def scan_one(digest):
    started=time.perf_counter();text=(HERE/'texts'/digest).read_text()
    result=dict(sha256=digest,bytes=len(text.encode()),matches=[],statements=[],license_error=None,holder_error=None)
    signal.signal(signal.SIGALRM,timeout)
    try:
        signal.alarm(30)
        t=time.perf_counter()
        for match in INDEX.match(query_string=text) or []:
            rule=match.rule
            result['matches'].append(dict(expression=rule.license_expression,spdx=spdx_primary(rule.license_expression),
                coverage=match.coverage(),score=match.score(),is_text=bool(textlike(rule,CANON) and rule.license_expression not in CANON.skip),
                start_line=match.start_line,end_line=match.end_line,rule=rule.identifier))
        result['license_seconds']=time.perf_counter()-t
    except Exception as ex:result['license_error']=type(ex).__name__+': '+str(ex)[:150]
    finally:signal.alarm(0)
    try:
        signal.alarm(30);t=time.perf_counter()
        result['statements']=notice_scan(text)
        result['holder_seconds']=time.perf_counter()-t
    except Exception as ex:result['holder_error']=type(ex).__name__+': '+str(ex)[:150]
    finally:signal.alarm(0)
    result['seconds']=time.perf_counter()-started
    return result

def refresh_notices(digest):
    result=json.loads((HERE/'scans'/(digest+'.json')).read_text())
    started=time.perf_counter()
    signal.signal(signal.SIGALRM,timeout)
    try:
        signal.alarm(30)
        result['statements']=notice_scan((HERE/'texts'/digest).read_text())
        result['holder_error']=None
    except Exception as ex:
        result['statements']=[]
        result['holder_error']=type(ex).__name__+': '+str(ex)[:150]
    finally:signal.alarm(0)
    result['notice_refinement_seconds']=time.perf_counter()-started
    return result

def fixtures():
    cases=[('Copyright 2024 Alice Example',True),
           ('Apache License\nVersion 2.0, January 2004\nCopyright Alice Example',False),
           ('Author: Alice Example\nReleased in 2024',False),
           ('Copyright [yyyy] [name of copyright owner]',False),
           ('Copyright (c) 2011 Michael Dowling <mtdowling@gmail.com>, 2016 Chris Tankersley <chris@ctankersley.com>, and contributors',True)]
    results=[]
    for text,want in cases:
        got=any(s['holder_and_year_present'] for s in notice_scan(text))
        results.append(dict(text=text,expected=want,actual=got,passed=got==want))
    separate=notice_scan('Copyright 2020 Bob Example\n\nCopyright Alice Example')
    results.append(dict(test='An unrelated notice year does not attach to Alice',passed=not any(
        'alice' in ' '.join(s['holders']) and s['holder_and_year_present'] for s in separate)))
    assert all(r['passed'] for r in results),results
    (HERE/'notice_parser_checks.json').write_text(json.dumps(results,indent=2)+'\n')

def main():
    global INDEX,CANON
    parser=argparse.ArgumentParser();parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--notices-only',action='store_true');args=parser.parse_args()
    (HERE/'scans').mkdir(exist_ok=True)
    digests=sorted({f['sha256'] for p in (HERE/'records').glob('*.json') for f in json.loads(p.read_text())['files'] if f['status']=='ok'})
    todo=digests if args.notices_only else [d for d in digests if not (HERE/'scans'/(d+'.json')).exists()]
    started=time.perf_counter()
    if not args.notices_only:
        from licensedcode.cache import get_index
        INDEX=get_index();CANON=canon_lengths(INDEX)
    fixtures()
    warm=time.perf_counter()-started
    print(json.dumps(dict(unique_readme_texts=len(digests),new_scans=len(todo),warmup_seconds=warm)),flush=True)
    phase=time.perf_counter();done=0
    with ProcessPoolExecutor(max_workers=args.workers,mp_context=multiprocessing.get_context('fork')) as pool:
        for future in as_completed([pool.submit(refresh_notices if args.notices_only else scan_one,d) for d in todo]):
            result=future.result();(HERE/'scans'/(result['sha256']+'.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
            done+=1
            if done%100==0:print(json.dumps(dict(done=done,total=len(todo),elapsed=time.perf_counter()-phase)),flush=True)
    run=dict(workers=args.workers,unique_readme_texts=len(digests),new_scans=len(todo),warmup_seconds=warm,
             scan_wall_seconds=time.perf_counter()-phase,total_seconds=time.perf_counter()-started,scancode_version='32.5.0')
    output='notice_refinement_run.json' if args.notices_only else 'scan_run.json'
    (HERE/output).write_text(json.dumps(run,indent=2)+'\n');print(json.dumps(run),flush=True)

if __name__=='__main__':main()
