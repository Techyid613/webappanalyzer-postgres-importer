"""Run: python3 -B -m unittest discover -s scripts -p 'test_repository_to_postgres.py'.

Set REPOSITORY_TEST_DSN to a disposable database to include PostgreSQL tests.
"""

import base64
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

import repository_to_postgres as exporter


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        (self.root / 'src/technologies').mkdir(parents=True)
        (self.root / 'src/images/icons').mkdir(parents=True)
        (self.root / '.git').mkdir()
        (self.root / '.git/HEAD').write_bytes(b'ref: refs/heads/main\n')
        (self.root / '.hidden/empty-directory').mkdir(parents=True)
        (self.root / 'empty-file').touch()
        self.name = "O'Reilly\t\\.\n雪"
        self.write_json('src/groups.json', {'1': {'name': 'Group'}})
        self.write_json('src/categories.json', {'1': {'name': 'Category', 'groups': [1, 999]}})
        self.write_json('src/technologies/a.json', {
            self.name: {
                'cats': [1, 999], 'requiresCategory': [1], 'website': 'https://example.com',
                'icon': "quote' icon.png", 'implies': [r'Child\;confidence:50\;version:\1', 'Child', 'Missing'],
                'requires': ['Child'], 'excludes': ['Child'],
                'dom': {'#selector': {'attributes': {'class': r'\w+\;confidence:50'}}},
                'future_field': {'false': False, 'empty': [], 'null': None},
            },
            'Child': {'cats': [1], 'website': 'https://example.org', 'icon': 'absent.svg'},
        })
        icon = self.root / "src/images/icons/quote' icon.png"
        icon.write_bytes(bytes(range(256)) + b'\n\\.\n\\N\t\r')
        icon.chmod(0o640)
        os.link(icon, self.root / 'hardlink')
        self.xattrs = {}
        try:
            os.setxattr(icon, 'user.snapshot-test', b'\x00\xffpayload')
            self.xattrs = {b'user.snapshot-test'.hex(): b'\x00\xffpayload'.hex()}
        except OSError as error:
            if error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP):
                raise
        (self.root / 'internal-link').symlink_to(icon.relative_to(self.root))
        (self.root / 'src/images/orphan.bin').write_bytes(b'unreferenced asset\x00\xff')

    def write_json(self, path, value):
        (self.root / path).write_text(json.dumps(value, ensure_ascii=False), encoding='utf8')

    def test_copy_escaping_and_manifest(self):
        self.assertEqual(exporter.copy_value('\\N\t\n\r'), r'\\N\t\n\r')
        self.assertEqual(exporter.copy_value(bytes([0, 255])), r'\\x00ff')
        expected = exporter.inventory(self.root)
        stream = io.StringIO()
        result = exporter.export(self.root, stream, 'test_archive')
        self.assertEqual(result['entry_count'], len(expected))
        self.assertEqual(result['counts']['symlink'], 1)
        self.assertIn('CREATE SCHEMA "test_archive";', stream.getvalue())
        self.assertIn('COMMIT;', stream.getvalue())

    def test_refuses_duplicate_json_keys(self):
        (self.root / 'src/groups.json').write_text('{"1": {}, "1": {}}')
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
            exporter.export(self.root, io.StringIO(), 'test_archive')

    def test_cli_output_protection(self):
        script = Path(exporter.__file__)
        output = Path(self.temp.name) / 'archive.sql'
        output.write_bytes(b'keep this existing file')
        for target in [output, self.root / 'archive.sql']:
            result = subprocess.run([sys.executable, '-B', str(script), str(self.root),
                                     '--output', str(target)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b'keep this existing file')
        self.assertFalse((self.root / 'archive.sql').exists())

    def test_refuses_external_dependencies(self):
        (self.root / 'external-link').symlink_to(Path(self.temp.name) / 'outside')
        with self.assertRaisesRegex(ValueError, 'External symlink'):
            exporter.export(self.root, io.StringIO(), 'test_archive')
        (self.root / 'external-link').unlink()
        (self.root / '.git/commondir').write_text('../../external-git')
        with self.assertRaisesRegex(ValueError, 'External Git storage'):
            exporter.export(self.root, io.StringIO(), 'test_archive')

    def test_source_change_aborts_export(self):
        original = exporter.read_bytes

        def changing_read(path, expected=None):
            result = original(path, expected)
            if path.name == 'empty-file':
                path.write_bytes(b'changed during export')
            return result

        with patch.object(exporter, 'read_bytes', changing_read):
            with self.assertRaisesRegex(ValueError, 'Source changed'):
                exporter.export(self.root, io.StringIO(), 'test_archive')

    def test_refuses_special_files_and_invalid_schema(self):
        with self.assertRaisesRegex(ValueError, 'Schema must'):
            exporter.export(self.root, io.StringIO(), 'bad"; DROP SCHEMA public;')
        os.mkfifo(self.root / 'pipe')
        with self.assertRaisesRegex(ValueError, 'special filesystem entry'):
            exporter.export(self.root, io.StringIO(), 'test_archive')

    def test_replaced_opened_file_and_fifo_are_rejected_without_blocking(self):
        path = self.root / 'empty-file'
        expected = path.stat()
        path.unlink()
        replacement = self.root / 'replacement'
        replacement.write_bytes(b'different inode')
        replacement.rename(path)
        with self.assertRaisesRegex(ValueError, 'Source changed before opening'):
            exporter.read_bytes(path, expected)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, 'Source changed before opening'):
            exporter.read_bytes(path, expected)

    def test_disk_full_is_propagated_before_publication(self):
        class FullDisk(io.StringIO):
            def write(self, value):
                raise OSError(errno.ENOSPC, 'No space left on device')
        with self.assertRaises(OSError) as failure:
            exporter.export(self.root, FullDisk(), 'test_archive')
        self.assertEqual(failure.exception.errno, errno.ENOSPC)

    @unittest.skipUnless(os.environ.get('REPOSITORY_TEST_DSN'), 'Set REPOSITORY_TEST_DSN for PostgreSQL round-trip')
    def test_postgres_round_trip_and_rollback(self):
        schema = 'test_archive_' + uuid.uuid4().hex
        failed_schema = schema + '_bad'
        dsn = os.environ['REPOSITORY_TEST_DSN']

        def sql(statement, succeeds=True):
            result = subprocess.run(['psql', '-X', '--set=ON_ERROR_STOP=1', '--dbname', dsn, '-At'],
                                    input=statement, text=True, capture_output=True)
            self.assertEqual(result.returncode == 0, succeeds, result.stderr)
            return result.stdout

        self.addCleanup(lambda: sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE; DROP SCHEMA IF EXISTS "{failed_schema}" CASCADE;'))
        # Read an exact JSON decimal directly from the source, without Python rounding.
        precise_path = self.root / 'src/technologies/a.json'
        precise_path.write_bytes(precise_path.read_bytes().replace(
            b'"future_field": {', b'"precise_number": 0.1234567890123456789012345, "future_field": {'))
        stream = io.StringIO()
        exporter.export(self.root, stream, schema)
        archive = stream.getvalue()
        imported = subprocess.run([sys.executable, '-B', str(Path(exporter.__file__)),
                                   str(self.root), '--database', dsn, '--schema', schema],
                                  capture_output=True, text=True)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        rows = sql(f'SELECT row_to_json(e) FROM (SELECT path, encode(content, \'base64\') AS payload, sha256, metadata FROM "{schema}".entries) e;')
        stored = {row['path']: row for row in map(json.loads, rows.splitlines())}
        self.assertEqual(set(stored), set(exporter.inventory(self.root)))
        for path, row in stored.items():
            source = self.root / path
            if source.is_symlink():
                expected = os.fsencode(os.readlink(source))
            elif source.is_file():
                expected = source.read_bytes()
            else:
                self.assertIsNone(row['payload'])
                continue
            self.assertEqual(base64.b64decode(row['payload']), expected, path)
            self.assertEqual(row['sha256'], hashlib.sha256(expected).hexdigest(), path)
            self.assertEqual(row['metadata']['st_mode'], source.lstat().st_mode)
        self.assertEqual(stored['hardlink']['metadata']['st_ino'],
                         stored["src/images/icons/quote' icon.png"]['metadata']['st_ino'])
        self.assertEqual(stored["src/images/icons/quote' icon.png"]['metadata']['xattrs_hex'], self.xattrs)
        self.assertEqual(sql(f'SELECT count(*) FROM "{schema}".unresolved_references;').strip(), '4')
        self.assertEqual(sql(f'SELECT count(*) FROM "{schema}".technology_relationships;').strip(), '5')
        definitions = sql(f'SELECT row_to_json(t) FROM "{schema}".technologies t;')
        self.assertEqual({t['name']: t['definition'] for t in map(json.loads, definitions.splitlines())},
                         json.loads((self.root / 'src/technologies/a.json').read_bytes()))
        tags = sql(f'SELECT tags FROM "{schema}".technology_relationships WHERE kind=\'implies\' AND position=1;')
        self.assertEqual(json.loads(tags), ['confidence:50', r'version:\1'])
        self.assertEqual(sql(f'SELECT definition->>\'precise_number\' FROM "{schema}".technologies WHERE definition ? \'precise_number\';').strip(),
                         '0.1234567890123456789012345')
        sql(archive, succeeds=False)
        self.assertEqual(sql(f'SELECT count(*) FROM "{schema}".technologies;').strip(), '2')
        bad = archive.replace(f'"{schema}"', f'"{failed_schema}"')
        checksum = hashlib.sha256((self.root / 'empty-file').read_bytes()).hexdigest()
        sql(bad.replace(checksum, '0' * 64), succeeds=False)
        self.assertEqual(sql(f"SELECT count(*) FROM pg_namespace WHERE nspname='{failed_schema}';").strip(), '0')


if __name__ == '__main__':
    unittest.main()
