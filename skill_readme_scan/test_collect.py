"""Offline, real-Git fixtures for immutable and scoped README collection."""
from pathlib import Path
import gzip
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('skill_readme_collect', Path(__file__).with_name('collect.py'))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.output = self.root / 'output'
        self.source.mkdir()
        self.output.mkdir()
        self.here = patch.object(collector, 'HERE', self.output)
        self.here.start()
        self.git('init', '--quiet')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'README test fixture')

    def tearDown(self):
        self.here.stop()
        self.temp.cleanup()

    def git(self, *args, cwd=None):
        return subprocess.run(['git', *args], cwd=cwd or self.source, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

    def write(self, path, content):
        full = self.source / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(content.encode() if isinstance(content, str) else content)

    def commit(self):
        self.git('add', '--all')
        self.git('commit', '--quiet', '-m', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def target(self, commit, directories, key='fixture'):
        # Pre-created local origin keeps every test offline while exercising the
        # same fetch, commit verification, ls-tree, and cat-file operations.
        bare = self.output / 'git' / key
        bare.mkdir(parents=True)
        self.git('init', '--bare', '--quiet', cwd=bare)
        self.git('remote', 'add', 'origin', str(self.source), cwd=bare)
        return dict(id=key, arm='skill', repo='fixture/repo', target_commit=commit,
                    selected_licence='mixed', stratum='missing_holder',
                    directories=directories, skill_occurrences=17)

    def test_exact_governing_directories_and_original_commit(self):
        for path in ('README.md', 'packages/read_me.txt', 'packages/selected/read-me.zh.md',
                     'packages/selected/README.py', 'packages/sibling/README.md',
                     'packages/selected/docs/README.md'):
            self.write(path, 'Copyright 2024 Original Owner\n')
        commit = self.commit()
        self.write('README.md', 'Copyright 2026 Later Owner\n')
        self.commit()
        target = self.target(commit, ['', 'packages', 'packages/selected'])
        result = collector.collect(target)
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(result['target_commit'], commit)
        self.assertEqual(result['resolved_commit'], commit)
        self.assertEqual(result['directories'], target['directories'])
        self.assertEqual(result['skill_occurrences'], 17)
        self.assertEqual({item['path'] for item in result['files']},
                         {'README.md', 'packages/read_me.txt', 'packages/selected/read-me.zh.md'})
        self.assertEqual([item['path'] for item in result['excluded_readme_candidates']],
                         ['packages/selected/README.py'])
        root = next(item for item in result['files'] if item['path'] == 'README.md')
        self.assertEqual((self.output / 'texts' / root['sha256']).read_bytes(),
                         b'Copyright 2024 Original Owner\n')
        with gzip.open(self.output / 'trees' / 'fixture.json.gz', 'rt') as stream:
            tree = json.load(stream)
        self.assertEqual(tree['commit'], commit)
        self.assertEqual(len(tree['files']), 4)
        self.assertEqual(tree['tree_blob_paths'], 6)

    def test_no_five_hundred_file_cap_and_chunked_reads(self):
        for index in range(513):
            self.write(f'collection/README.lang{index}.md', f'Copyright 2024 Owner {index}\n')
        target = self.target(self.commit(), ['collection'])
        original = collector.read_objects
        chunk_lengths = []

        def tracked(directory, blobs, timeout):
            chunk_lengths.append(len(blobs))
            return original(directory, blobs, timeout)

        with patch.object(collector, 'read_objects', side_effect=tracked):
            result = collector.collect(target)
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(len(result['files']), 513)
        self.assertEqual(result['readmes_discovered'], 513)
        self.assertFalse(result['readme_cap_reached'])
        self.assertGreater(len(chunk_lengths), 1)
        self.assertLessEqual(max(chunk_lengths), collector.BLOB_CHUNK)

    def test_only_hash_verified_seed_present_in_pinned_tree_is_reused(self):
        first = b'Copyright 2022 Cached Owner\r\n'
        second = b'Copyright 2023 Fetched Owner\n'
        absent = b'Copyright 2024 Not In This Commit\n'
        self.write('README.md', first)
        self.write('README.fr.md', second)
        target = self.target(self.commit(), [''])
        seeds = self.output / 'seed_blobs'
        seeds.mkdir()
        (seeds / collector.gitblob(first)).write_bytes(first)
        (seeds / collector.gitblob(second)).write_bytes(b'corrupt bytes')
        (seeds / collector.gitblob(absent)).write_bytes(absent)
        result = collector.collect(target)
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(result['cached_unique_blobs_reused'], 1)
        self.assertEqual(len(result['seed_cache_rejections']), 1)
        self.assertEqual(len(result['files']), 2)
        root = next(item for item in result['files'] if item['path'] == 'README.md')
        self.assertEqual(root['retrieved_from'], 'verified_seed')
        self.assertTrue(root['raw_blob_verified'])
        self.assertEqual(root['text_decoding'], 'utf-8-replace')
        self.assertEqual(root['git_blob'], collector.gitblob(first))
        self.assertEqual(root['raw_sha256'], collector.sha(first))
        self.assertEqual(root['bytes'], len(first))
        self.assertEqual((self.output / 'texts' / root['sha256']).read_bytes(), first)

    def test_symlink_binary_and_oversize_candidates_remain_explicit(self):
        self.write('README.binary', b'not\0text')
        self.write('README.large.md', b'A' * (collector.MAX_BYTES + 1))
        self.write('README.md', 'Copyright 2024 Reader\n')
        os.symlink('README.md', self.source / 'README.link')
        target = self.target(self.commit(), [''])
        result = collector.collect(target)
        self.assertEqual(result['status'], 'partial', result)
        statuses = {item['path']: item['status'] for item in result['files']}
        self.assertEqual(statuses, {'README.binary': 'binary', 'README.large.md': 'oversize',
                                   'README.md': 'ok', 'README.link': 'symlink'})
        self.assertTrue(result['retrieval_complete'])
        self.assertEqual(result['skipped_symlink_readmes'], ['README.link'])

    def test_failed_blob_chunk_keeps_other_collected_readmes(self):
        first = b'Copyright 2020 Available Owner\n'
        second = b'Copyright 2021 Missing Owner\n'
        self.write('README.md', first)
        self.write('README.fr.md', second)
        target = self.target(self.commit(), [''])
        failed = collector.gitblob(second)
        original_sizes = collector.object_sizes
        original_command = collector.command

        def sizes_without_missing(directory, blobs, timeout):
            return {blob: size for blob, size in original_sizes(directory, blobs, timeout).items()
                    if blob != failed}

        def timeout_only_blob_fetch(args, cwd, timeout=120, inp=None):
            if '--stdin' in args:
                raise subprocess.TimeoutExpired(args, timeout)
            return original_command(args, cwd, timeout, inp)

        with patch.object(collector, 'object_sizes', side_effect=sizes_without_missing), \
             patch.object(collector, 'command', side_effect=timeout_only_blob_fetch):
            result = collector.collect(target)
        self.assertEqual(result['status'], 'partial', result)
        self.assertFalse(result['retrieval_complete'])
        self.assertEqual({item['path']: item['status'] for item in result['files']},
                         {'README.md': 'ok', 'README.fr.md': 'unavailable'})
        error = next(error for error in result['collection_errors'] if error['phase'] == 'fetch_blob_chunk')
        self.assertTrue(error['timeout'])
        self.assertEqual(error['timeout_seconds'], collector.FETCH_TIMEOUT)
        self.assertEqual(error['git_blobs'], [failed])

    def test_commit_mismatch_is_never_accepted(self):
        self.write('README.md', 'Copyright 2020 Owner')
        target = self.target(self.commit(), [''])
        original = collector.command

        def mismatched(args, cwd, timeout=120, inp=None):
            if 'rev-parse' in args:
                return b'0000000000000000000000000000000000000000\n'
            return original(args, cwd, timeout, inp)

        with patch.object(collector, 'command', side_effect=mismatched):
            result = collector.collect(target)
        self.assertEqual(result['status'], 'error')
        self.assertFalse(result['inventory_complete'])
        self.assertEqual(result['files'], [])
        self.assertIn('does not match', result['error'])


if __name__ == '__main__':
    unittest.main()
