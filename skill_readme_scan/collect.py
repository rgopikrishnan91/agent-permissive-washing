"""Recover scoped Skill README documents at immutable study commits.

Only Git objects are read. No checkout, repository scripts, or harvested code
are executed. Missing or unscannable candidates remain explicit in the records.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent
ENV = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': 'true',
       'GIT_LFS_SKIP_SMUDGE': '1', 'GIT_NO_LAZY_FETCH': '1'}
README = re.compile(r'^read[ _-]?me(?:[._-].*)?$', re.I)
SOURCE_SUFFIXES = frozenset('''py pyc pyo ipynb js jsx mjs cjs ts tsx c cc cpp cxx h
hpp hxx java class jar go rs rb php swift kt kts scala sh bash zsh fish ps1 bat
cmd sql r lua pl pm ex exs erl hrl hs lhs ml mli clj cljs cljc fs fsx cs vb vbs
vba ino asm s sol vue svelte dockerfile cmake gradle'''.split())
MAX_BYTES = 1_000_000
BLOB_CHUNK = 64
FETCH_TIMEOUT = 180
OBJECT_TIMEOUT = 90
REPO_SECONDS = 900


def sha(data):
    return hashlib.sha256(data).hexdigest()


def gitblob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def command(args, cwd, timeout=120, inp=None):
    result = subprocess.run(args, cwd=cwd, env=ENV, input=inp,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8', 'replace')[-700:])
    return result.stdout


def excluded_source_name(path):
    base = path.rsplit('/', 1)[-1].lower()
    return '.' in base and base.rsplit('.', 1)[-1] in SOURCE_SUFFIXES


def binary(data):
    if b'\0' in data:
        return True
    controls = sum(byte < 32 and byte not in (9, 10, 12, 13) for byte in data)
    return bool(data and controls / len(data) > 0.02)


def record_error(result, phase, ex, blobs=None):
    error = dict(phase=phase, error=type(ex).__name__ + ': ' + str(ex)[:500],
                 timeout=isinstance(ex, (subprocess.TimeoutExpired, TimeoutError)))
    if isinstance(ex, subprocess.TimeoutExpired):
        error['timeout_seconds'] = ex.timeout
    if blobs is not None:
        error['git_blobs'] = list(blobs)
    result['collection_errors'].append(error)
    return error


def store_text(data):
    text_bytes = data.decode('utf-8', 'replace').encode('utf-8')
    digest = sha(text_bytes)
    # Concurrent repositories may share a digest; the bytes are identical.
    (HERE / 'texts' / digest).write_bytes(text_bytes)
    return digest


def accept_blob(blob, data, origin):
    if gitblob(data) != blob:
        raise ValueError('Git blob hash mismatch: ' + blob)
    entry = dict(git_blob=blob, raw_sha256=sha(data), bytes=len(data),
                 retrieved_from=origin, raw_blob_verified=True,
                 text_decoding='utf-8-replace')
    entry['status'] = ('oversize' if len(data) > MAX_BYTES else
                       'binary' if binary(data) else 'ok')
    if entry['status'] == 'ok':
        entry['sha256'] = store_text(data)
    return entry


def object_sizes(directory, blobs, timeout):
    raw = command(['git', 'cat-file', '--batch-check'], directory, timeout,
                  ('\n'.join(blobs) + '\n').encode())
    sizes = {}
    for line in raw.splitlines():
        fields = line.decode('ascii').split()
        if len(fields) == 3 and fields[1] == 'blob':
            sizes[fields[0]] = int(fields[2])
    return sizes


def read_objects(directory, blobs, timeout):
    raw = command(['git', 'cat-file', '--batch'], directory, timeout,
                  ('\n'.join(blobs) + '\n').encode())
    position = 0
    for expected in blobs:
        end = raw.index(b'\n', position)
        fields = raw[position:end].decode('ascii').split()
        position = end + 1
        if len(fields) != 3 or fields[:2] != [expected, 'blob']:
            raise ValueError('Missing requested blob: ' + expected)
        size = int(fields[2])
        data = raw[position:position + size]
        position += size + 1
        if len(data) != size or raw[position - 1:position] != b'\n':
            raise ValueError('Truncated batch blob: ' + expected)
        yield expected, data
    if position != len(raw):
        raise ValueError('Unexpected trailing Git batch output')


def collect(target):
    started = time.perf_counter()
    result = {key: target[key] for key in
              ('id', 'arm', 'repo', 'target_commit', 'selected_licence',
               'stratum', 'directories', 'skill_occurrences')}
    result.update(files=[], context_files=[], collection_errors=[],
                  excluded_readme_candidates=[], skipped_symlink_readmes=[],
                  readme_cap_reached=False, baseline_root_context_unchanged=True,
                  current_root_context_paths=[], cached_readme_blobs_reused=0,
                  cached_unique_blobs_reused=0, fetched_blobs=0,
                  seed_cache_rejections=[], inventory_complete=False,
                  readme_filename_policy='read[ _-]?me with optional dot/underscore/hyphen suffix; known source suffixes excluded',
                  max_document_bytes=MAX_BYTES, blob_chunk_size=BLOB_CHUNK,
                  repository_time_budget_seconds=REPO_SECONDS)
    phase = 'validate_target'
    try:
        commit = target['target_commit']
        if not commit:
            return dict(result, status='no_pinned_commit', seconds=time.perf_counter() - started)
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('Invalid immutable commit')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', target['repo']):
            raise ValueError('Invalid GitHub repository')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', target['id']):
            raise ValueError('Invalid target identifier')
        directories = set(target['directories'])
        if not directories or any(path and (path.startswith('/') or
                any(part in ('', '.', '..') for part in path.split('/'))) for path in directories):
            raise ValueError('Target directories must be canonical relative Git paths')
        for folder in ('git', 'texts', 'trees', 'records'):
            (HERE / folder).mkdir(exist_ok=True)
        directory = HERE / 'git' / target['id']
        directory.mkdir(parents=True, exist_ok=True)
        phase = 'initialize_git'
        if not (directory / 'config').exists():
            command(['git', 'init', '--bare', '--quiet'], directory)
            command(['git', 'remote', 'add', 'origin',
                     'https://github.com/' + target['repo'] + '.git'], directory)
        network_started = time.perf_counter()
        phase = 'fetch_pinned_commit'
        command(['git', 'fetch', '--depth=1', '--filter=blob:none', '--no-tags',
                 '--quiet', 'origin', commit], directory, FETCH_TIMEOUT)
        phase = 'verify_pinned_commit'
        resolved = command(['git', 'rev-parse', 'FETCH_HEAD^{commit}'], directory).decode().strip()
        if resolved != commit:
            raise ValueError('Fetched commit does not match target commit')
        result['resolved_commit'] = resolved
        phase = 'inventory_pinned_tree'
        raw_tree = command(['git', 'ls-tree', '-r', '-z', commit], directory, 120)
        tree = {}
        blob_paths = 0
        for raw_entry in raw_tree.split(b'\0'):
            if not raw_entry:
                continue
            metadata, raw_path = raw_entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode('ascii').split()
            if kind != 'blob':
                continue
            blob_paths += 1
            path = raw_path.decode('utf-8', 'surrogateescape')
            parent, _, basename = path.rpartition('/')
            if parent in directories and README.fullmatch(basename):
                tree[path] = (mode, blob)
        result['tree_blob_paths'] = blob_paths
        result['readmes_discovered'] = len(tree)
        result['inventory_complete'] = True
        result['directory_count'] = len(directories)
        # The full tree is inventoried above; only applicable candidates need
        # archiving. Git commit identity fixes membership for reused blobs.
        with gzip.open(HERE / 'trees' / (target['id'] + '.json.gz'), 'wt') as stream:
            json.dump(dict(commit=commit, scope='README candidates directly in target directories',
                           directories=target['directories'], tree_blob_paths=blob_paths,
                           files={path: dict(mode=mode, git_blob=blob)
                                  for path, (mode, blob) in sorted(tree.items())}), stream, sort_keys=True)
        selected = []
        entries = {}
        for path, (mode, blob) in sorted(tree.items()):
            if excluded_source_name(path):
                result['excluded_readme_candidates'].append(dict(path=path, git_blob=blob,
                    mode=mode, reason='source_code_filename'))
                continue
            selected.append(path)
            if mode == '120000':
                result['skipped_symlink_readmes'].append(path)
                entries[path] = dict(path=path, git_blob=blob, mode=mode, status='symlink')
            elif mode not in ('100644', '100755'):
                entries[path] = dict(path=path, git_blob=blob, mode=mode, status='unsupported_mode')
        result['readmes_selected'] = len(selected)
        wanted = sorted({tree[path][1] for path in selected if path not in entries})
        blobs = {}
        phase = 'verify_seed_blobs'
        for blob in wanted:
            seed = HERE / 'seed_blobs' / blob
            if not seed.is_file():
                continue
            try:
                data = seed.read_bytes()
                blobs[blob] = accept_blob(blob, data, 'verified_seed')
                result['cached_unique_blobs_reused'] += 1
            except Exception as ex:
                result['seed_cache_rejections'].append(dict(git_blob=blob, error=str(ex)[:250]))
        result['cached_readme_blobs_reused'] = sum(tree[path][1] in blobs for path in selected)
        missing = [blob for blob in wanted if blob not in blobs]
        phase = 'retrieve_readme_blobs'
        for start in range(0, len(missing), BLOB_CHUNK):
            chunk = missing[start:start + BLOB_CHUNK]
            remaining = REPO_SECONDS - (time.perf_counter() - started)
            if remaining <= 0:
                record_error(result, 'repository_time_budget', TimeoutError('Repository time budget exhausted'),
                             missing[start:])
                for blob in missing[start:]:
                    blobs[blob] = dict(git_blob=blob, status='unavailable',
                                       error='repository_time_budget_exhausted')
                break
            # Check objects already available after the shallow fetch, including
            # any partial successes from earlier interrupted collection attempts.
            try:
                sizes = object_sizes(directory, chunk, min(OBJECT_TIMEOUT, remaining))
            except Exception as ex:
                record_error(result, 'check_local_blobs', ex, chunk)
                sizes = {}
            absent = [blob for blob in chunk if blob not in sizes]
            if absent:
                try:
                    remaining = max(1, REPO_SECONDS - (time.perf_counter() - started))
                    command(['git', '-c', 'fetch.negotiationAlgorithm=noop', 'fetch', '--quiet',
                             '--no-tags', '--no-write-fetch-head', '--recurse-submodules=no',
                             '--filter=blob:none', '--stdin', 'origin'], directory,
                            min(FETCH_TIMEOUT, remaining), ('\n'.join(absent) + '\n').encode())
                except Exception as ex:
                    record_error(result, 'fetch_blob_chunk', ex, absent)
                try:
                    remaining = max(1, REPO_SECONDS - (time.perf_counter() - started))
                    sizes = object_sizes(directory, chunk, min(OBJECT_TIMEOUT, remaining))
                except Exception as ex:
                    record_error(result, 'check_fetched_blobs', ex, chunk)
            readable = []
            for blob in chunk:
                if blob not in sizes:
                    blobs[blob] = dict(git_blob=blob, status='unavailable', error='Git blob unavailable after fetch')
                elif sizes[blob] > MAX_BYTES:
                    blobs[blob] = dict(git_blob=blob, bytes=sizes[blob], status='oversize',
                                       retrieved_from='git_object')
                else:
                    readable.append(blob)
            if readable:
                try:
                    remaining = max(1, REPO_SECONDS - (time.perf_counter() - started))
                    for blob, data in read_objects(directory, readable, min(OBJECT_TIMEOUT, remaining)):
                        try:
                            blobs[blob] = accept_blob(blob, data, 'git_object')
                            result['fetched_blobs'] += 1
                        except Exception as ex:
                            blobs[blob] = dict(git_blob=blob, status='hash_error', error=str(ex)[:250])
                except Exception as ex:
                    record_error(result, 'read_blob_chunk', ex, readable)
                for blob in readable:
                    if blob not in blobs:
                        blobs[blob] = dict(git_blob=blob, status='unavailable', error='Unable to read Git blob')
            # Keep completed candidates in the result even if a later chunk fails.
            result['files'] = [entries.get(path) or dict(path=path, mode=tree[path][0], **blobs[tree[path][1]])
                               for path in selected if path in entries or tree[path][1] in blobs]
        result['files'] = [entries.get(path) or dict(path=path, mode=tree[path][0], **blobs[tree[path][1]])
                           for path in selected]
        result['network_seconds'] = time.perf_counter() - network_started
        result['status'] = 'partial' if any(item['status'] != 'ok' for item in result['files']) else 'ok'
        result['retrieval_complete'] = not any(item['status'] in {'unavailable', 'hash_error'}
                                              for item in result['files'])
    except Exception as ex:
        record_error(result, phase, ex)
        result.update(status='timeout' if isinstance(ex, subprocess.TimeoutExpired) else 'error',
                      error=str(ex)[:800], retrieval_complete=False)
    result['seconds'] = time.perf_counter() - started
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--limit', type=int)
    args = parser.parse_args()
    for folder in ('git', 'texts', 'trees', 'records'):
        (HERE / folder).mkdir(exist_ok=True)
    targets = json.loads((HERE / 'targets.json').read_text())
    todo = [target for target in targets if not (HERE / 'records' / (target['id'] + '.json')).exists()]
    if args.limit:
        todo = todo[:args.limit]
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for done, future in enumerate(as_completed([pool.submit(collect, target) for target in todo]), 1):
            result = future.result()
            (HERE / 'records' / (result['id'] + '.json')).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
            print(json.dumps(dict(done=done, total=len(todo), repo=result['repo'], arm=result['arm'],
                  status=result['status'], readmes=len(result['files']), seconds=round(result['seconds'], 2),
                  elapsed=round(time.perf_counter() - started, 1))), flush=True)
    (HERE / 'collection_run.json').write_text(json.dumps(dict(workers=args.workers,
        attempted=len(todo), elapsed_seconds=time.perf_counter() - started), indent=2) + '\n')


if __name__ == '__main__':
    main()
