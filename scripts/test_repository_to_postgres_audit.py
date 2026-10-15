"""Independent CLI/real-PostgreSQL audit; never imports the exporter.

python3 -B -m unittest discover -s scripts -p 'test_repository_to_postgres*.py'
REPOSITORY_TEST_DSN enables real DB tests (requires CREATE DATABASE).
REPOSITORY_AUDIT_SOURCE additionally audits the full source checkout.
REPOSITORY_TEST_CONTAINER enables archive-only restore with docker exec.
"""

import base64
from decimal import Decimal
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


SCRIPT = Path(__file__).with_name('repository_to_postgres.py').resolve()
DSN = os.environ.get('REPOSITORY_TEST_DSN')


def file_bytes(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOATIME', 0))
    with os.fdopen(fd, 'rb') as stream:
        return stream.read()


def source_snapshot(root):
    """Independent source-of-truth reader: bytes and every available stat/xattr."""
    result = {}
    pending = [root]
    while pending:
        path = pending.pop()
        info = os.lstat(path)
        relative = path.relative_to(root).as_posix()
        meta = {k: getattr(info, k) for k in dir(info) if k.startswith('st_')}
        meta['xattrs_hex'] = {os.fsencode(k).hex(): os.getxattr(path, k, follow_symlinks=False).hex()
                              for k in os.listxattr(path, follow_symlinks=False)}
        if stat.S_ISDIR(info.st_mode):
            kind, payload = 'directory', None
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOATIME', 0))
            try:
                with os.scandir(fd) as entries:
                    pending.extend(path / entry.name for entry in entries)
            finally:
                os.close(fd)
        elif stat.S_ISLNK(info.st_mode):
            kind, payload = 'symlink', os.fsencode(os.readlink(path))
            link_path = os.path.relpath(os.path.realpath(path), root)
            # readlink itself can update symlink atime; baseline after observing it.
            info = os.lstat(path)
            meta.update({k: getattr(info, k) for k in dir(info) if k.startswith('st_')})
        else:
            kind, payload = 'file', file_bytes(path)
        result[relative] = dict(kind=kind, payload=payload, metadata=meta,
                                link_path=link_path if kind == 'symlink' else None)
    return result


def psql(dsn, sql=None, archive=None):
    args = ['psql', '-X', '-w', '--set=ON_ERROR_STOP=1', '--dbname', dsn, '-At']
    if archive:
        args += ['--file', str(archive)]
    return subprocess.run(args, input=sql, text=True, capture_output=True, timeout=120)


def rows(dsn, query):
    result = psql(dsn, f'SELECT row_to_json(row) FROM ({query}) row;')
    if result.returncode:
        raise AssertionError(result.stderr)
    return [json.loads(line, parse_float=Decimal) for line in result.stdout.splitlines()]


def verify_database(case, dsn, expected, schema='webappanalyzer'):
    """Compare to independent source bytes, not importer counts or hashes."""
    query = f'''SELECT row_to_json(row) FROM (
        SELECT path, parent_path, encode(path_bytes,'hex') AS path_hex,
               kind, metadata_json, metadata, media_type, link_path,
               encode(content,'base64') AS payload, sha256, entry_sha256
        FROM "{schema}".entries ORDER BY path COLLATE "C"
    ) row;'''
    process = subprocess.Popen(['psql', '-X', '-w', '--set=ON_ERROR_STOP=1', '--dbname', dsn,
                                '-At', '-c', query], stdout=subprocess.PIPE, text=True)
    seen = set()
    fingerprints = {}
    for line in process.stdout:
        row = json.loads(line)
        path = row['path']
        case.assertIn(path, expected)
        case.assertNotIn(path, seen)
        seen.add(path)
        original = expected[path]
        case.assertEqual(row['kind'], original['kind'], path)
        case.assertEqual(row['parent_path'], None if path == '.' else Path(path).parent.as_posix(), path)
        case.assertEqual(row['path_hex'], os.fsencode(path).hex(), path)
        case.assertEqual(row['metadata'], original['metadata'], path)
        case.assertEqual(json.loads(row['metadata_json']), original['metadata'], path)
        case.assertEqual(row['link_path'], original['link_path'], path)
        case.assertEqual(row['media_type'], mimetypes.guess_type(path)[0] if original['kind'] == 'file' else None, path)
        actual = None if row['payload'] is None else base64.b64decode(row['payload'])
        case.assertEqual(actual, original['payload'], path)
        case.assertEqual(row['sha256'], None if actual is None else hashlib.sha256(actual).hexdigest(), path)
        fingerprints[path] = row['entry_sha256']
    process.stdout.close()
    case.assertEqual(process.wait(timeout=120), 0)
    case.assertEqual(seen, set(expected))
    case.assertEqual({r['tablename'] for r in rows(dsn, f"SELECT tablename FROM pg_tables WHERE schemaname='{schema}'")},
                     {'entries', 'snapshot', 'groups', 'categories', 'technologies', 'category_groups',
                      'technology_categories', 'technology_relationships', 'technology_icons'})
    case.assertEqual({r['viewname'] for r in rows(dsn, f"SELECT viewname FROM pg_views WHERE schemaname='{schema}'")},
                     {'assets', 'technology_fields', 'unresolved_references'})

    definitions = {}
    for table, key in [('groups', 'id'), ('categories', 'id'), ('technologies', 'name')]:
        wanted = {}
        for path, entry in expected.items():
            selected = path == f'src/{table}.json' if table != 'technologies' else (
                Path(path).parent.as_posix() == 'src/technologies' and path.endswith('.json'))
            if selected:
                document = json.loads(entry['payload'].decode('utf-8-sig'), parse_float=Decimal)
                for name, value in document.items():
                    wanted[name] = dict(**{key: name}, source_path=path, definition=value)
        actual = rows(dsn, f'SELECT * FROM "{schema}".{table}')
        case.assertEqual({row[key]: row for row in actual}, wanted, table)
        definitions[table] = {k: v['definition'] for k, v in wanted.items()}

    techs, cats, groups = (definitions[k] for k in ['technologies', 'categories', 'groups'])
    category_links, relationships, group_links, icons = [], [], [], []
    unresolved = []
    for cid, category in cats.items():
        for position, gid in enumerate(category.get('groups', []), 1):
            gid = str(gid)
            group_links.append(dict(category_id=cid, position=position, group_id=gid,
                                    resolved_group_id=gid if gid in groups else None))
            if gid not in groups:
                unresolved.append((cid, 'groups', gid))
    for name, technology in techs.items():
        for kind in ['cats', 'requiresCategory']:
            for position, cid in enumerate(technology.get(kind, []), 1):
                cid = str(cid)
                category_links.append(dict(technology_name=name, kind=kind, position=position,
                                            category_id=cid, resolved_category_id=cid if cid in cats else None))
                if cid not in cats:
                    unresolved.append((name, kind, cid))
        for kind in ['implies', 'requires', 'excludes']:
            for position, raw in enumerate(technology.get(kind, []), 1):
                target, *tags = raw.split('\\;')
                relationships.append(dict(technology_name=name, kind=kind, position=position, raw_value=raw,
                                          target_name=target, tags=tags, resolved_target_name=target if target in techs else None))
                if target not in techs:
                    unresolved.append((name, kind, target))
        if 'icon' in technology:
            path = 'src/images/icons/' + technology['icon']
            asset = expected.get(path)
            if asset and asset['kind'] == 'symlink':
                path = asset['link_path']
                asset = expected.get(path)
            resolved = path if asset and asset['kind'] == 'file' else None
            icons.append(dict(technology_name=name, icon_name=technology['icon'], file_path=resolved))
            if resolved is None:
                unresolved.append((name, 'icon', technology['icon']))
    for table, wanted, key in [
        ('category_groups', group_links, lambda r: (r['category_id'], r['position'])),
        ('technology_categories', category_links, lambda r: (r['technology_name'], r['kind'], r['position'])),
        ('technology_relationships', relationships, lambda r: (r['technology_name'], r['kind'], r['position'])),
        ('technology_icons', icons, lambda r: r['technology_name']),
    ]:
        case.assertEqual(sorted(rows(dsn, f'SELECT * FROM "{schema}".{table}'), key=key), sorted(wanted, key=key), table)
    actual_fields = rows(dsn, f'SELECT * FROM "{schema}".technology_fields')
    case.assertEqual({(r['technology_name'], r['field']): r['value'] for r in actual_fields},
                     {(name, field): value for name, tech in techs.items() for field, value in tech.items()})
    case.assertEqual({r['path'] for r in rows(dsn, f'SELECT path FROM "{schema}".assets')},
                     {p for p, e in expected.items() if p.startswith('src/images/') and e['kind'] == 'file'})
    case.assertEqual(sorted((r['source'], r['kind'], r['target']) for r in rows(dsn, f'SELECT * FROM "{schema}".unresolved_references')), sorted(unresolved))
    snapshots = rows(dsn, f'SELECT * FROM "{schema}".snapshot')
    case.assertEqual(len(snapshots), 1)
    case.assertEqual(snapshots[0]['format_version'], 2)
    case.assertEqual(snapshots[0]['manifest']['manifest_sha256'], hashlib.sha256(
        ''.join(fingerprints[p] for p in sorted(fingerprints)).encode('ascii')).hexdigest())
    return dict(entries=len(expected), files=sum(e['kind'] == 'file' for e in expected.values()),
                payload_bytes=sum(len(e['payload']) for e in expected.values() if e['payload'] is not None),
                images=sum(p.startswith('src/images/') and e['kind'] == 'file' for p, e in expected.items()),
                image_payload_bytes=sum(len(e['payload']) for p, e in expected.items() if p.startswith('src/images/') and e['kind'] == 'file'),
                metadata_fields=sum(len(e['metadata']) for e in expected.values()), technologies=len(techs),
                categories=len(cats), groups=len(groups), category_group_links=len(group_links),
                technology_category_links=len(category_links), technology_relationships=len(relationships),
                icon_links=len(icons), unresolved=len(unresolved), snapshot=snapshots[0])


class AuditFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='repository-independent-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / 'source'
        (self.source / 'src/technologies').mkdir(parents=True)
        (self.source / 'src/images/icons').mkdir(parents=True)
        self.document('src/groups.json', {'1': {'name': 'Group', 'unknown': {'keep': True}}})
        self.document('src/categories.json', {'1': {'name': 'Category', 'groups': [1, 99, 1]}})
        self.document('src/technologies/a.json', {
            "O'Reilly\t\n\\.雪😀": {'cats': [1, 99, 1], 'website': 'https://example.test', 'saas': False,
                                  'requiresCategory': [1], 'implies': [r'Other\;confidence:50\;version:\1', 'Other', 'Absent'],
                                  'requires': ['Other'], 'excludes': ['Other'], 'icon': 'alias.png',
                                  'future': {'empty': [], 'null': None, 'nested': {'a': 0}}},
            'Other': {'cats': [1], 'saas': True, 'icon': 'missing.svg'},
        })
        for name, payload in [('all-bytes.bin', bytes(range(256)) * 256), ('empty', b''),
                              ("quotes'\tline\n\\N", b'\\.\n\\N\r\t\x00\xff'), ('雪😀', b'unicode'),
                              ('controls\x01\b\v\f', b'controls')]:
            (self.source / name).write_bytes(payload)
        (self.source / '.hidden/empty-dir').mkdir(parents=True)
        image = self.source / 'src/images/shared.png'
        image.write_bytes(bytes(range(256)))
        os.link(image, self.source / 'hardlink')
        os.setxattr(image, b'user.audit-\xff', b'\x00\xffmetadata')
        (self.source / 'src/images/icons/alias.png').symlink_to('../shared.png')
        (self.source / 'dangling').symlink_to('missing-local-file')
        (self.source / 'directory-link').symlink_to('.hidden')
        (self.source / '.git').mkdir()
        (self.source / '.git/HEAD').write_bytes(b'ref: refs/heads/main\n')
        self.standalone = self.work / 'standalone.py'
        shutil.copyfile(SCRIPT, self.standalone)

    def document(self, path, value):
        (self.source / path).write_text(json.dumps(value, ensure_ascii=False), encoding='utf8')

    def cli(self, *args, env=None):
        return subprocess.run([sys.executable, '-B', str(self.standalone), str(self.source), *map(str, args)],
                              text=True, capture_output=True, env=env, timeout=120)

    def archive(self, schema='webappanalyzer'):
        output = self.work / ('archive-' + uuid.uuid4().hex + '.sql')
        result = self.cli('--output', output, '--schema', schema)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        return output


class CliAudit(AuditFixture):
    def test_invalid_documents_fail_before_publication(self):
        path = self.source / 'src/technologies/a.json'
        cases = ['{', '[]', '{"X":1}', '{"X":{},"X":{}}', '{"X":{"nested":{"a":1,"a":2}}}',
                 '{"X":{"cats":1}}', '{"X":{"requires":[null]}}', '{"X":{"icon":null}}',
                 '{"X":{"value":NaN}}', '{"X":{"value":Infinity}}', '{"X":{"value":"\\u0000"}}',
                 '{"X":{"value":"\\ud800"}}', '{"X":{"value":1e131072}}', '{"X":{"value":1e-16384}}']
        for value in cases:
            with self.subTest(value=value):
                path.write_text(value)
                output = self.work / 'must-not-exist.sql'
                result = self.cli('--output', output)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertFalse(list(self.work.glob('repository-*.sql')))
        path.write_bytes('{"X":{}}'.encode('utf16'))
        self.assertNotEqual(self.cli('--output', self.work / 'utf16.sql').returncode, 0)

    def test_duplicate_names_between_shards(self):
        shutil.copyfile(self.source / 'src/technologies/a.json', self.source / 'src/technologies/b.json')
        result = self.cli('--output', self.work / 'duplicate.sql')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Duplicate technology', result.stderr)

    def test_existing_and_inside_outputs_are_untouched(self):
        existing = self.work / 'existing.sql'
        existing.write_bytes(b'existing data')
        for target in [existing, self.source / 'inside.sql']:
            self.assertNotEqual(self.cli('--output', target).returncode, 0)
        alias = self.work / 'source-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        self.assertNotEqual(self.cli('--output', alias / 'inside.sql').returncode, 0)
        dangling = self.work / 'dangling.sql'
        dangling.symlink_to(self.work / 'nonexistent.sql')
        self.assertNotEqual(self.cli('--output', dangling).returncode, 0)
        self.assertTrue(dangling.is_symlink())
        self.assertEqual(existing.read_bytes(), b'existing data')
        self.assertFalse((self.source / 'inside.sql').exists())

    def test_schema_names_and_missing_psql(self):
        for schema in ['pg_bad', 'a' * 64, 'a";DROP SCHEMA public;', '']:
            self.assertNotEqual(self.cli('--output', self.work / 'bad.sql', '--schema', schema).returncode, 0)
        self.archive('a' * 63)
        result = self.cli('--database', 'unused', env=dict(os.environ, PATH=''))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('psql is required', result.stderr)

    def test_external_git_storage_at_nested_locations(self):
        for relative in ['nested/.git', '.git/modules/module/objects/info/alternates',
                         '.git/modules/module/commondir']:
            with self.subTest(relative=relative):
                path = self.source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('/outside/required/storage')
                result = self.cli('--output', self.work / 'bad.sql')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('External Git storage', result.stderr)
                path.unlink()

    def test_special_files_external_links_and_undecodable_names(self):
        path = self.source / 'unsupported'
        actions = [lambda: os.mkfifo(path), lambda: path.symlink_to('/etc/passwd')]
        for create in actions:
            create()
            self.assertNotEqual(self.cli('--output', self.work / 'bad.sql').returncode, 0)
            path.unlink()
        raw_path = os.fsencode(self.source) + b'/invalid-\xff'
        fd = os.open(raw_path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        self.assertNotEqual(self.cli('--output', self.work / 'bad.sql').returncode, 0)

    def test_unreadable_and_oversized_files(self):
        path = self.source / 'restricted'
        path.write_bytes(b'cannot read')
        path.chmod(0)
        try:
            self.assertNotEqual(self.cli('--output', self.work / 'bad.sql').returncode, 0)
        finally:
            path.chmod(0o600)
        with path.open('wb') as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        result = self.cli('--output', self.work / 'bad.sql')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bytea safety limit', result.stderr)

    def pause_export(self):
        with (self.source / 'large.bin').open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        env = dict(os.environ, TMPDIR=str(self.work))
        output = self.work / 'interrupted.sql'
        process = subprocess.Popen([sys.executable, '-B', str(self.standalone), str(self.source), '--output', str(output)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            staging = list(self.work.glob('repository-*.sql'))
            if staging and staging[0].stat().st_size > 0 and process.poll() is None:
                process.send_signal(signal.SIGSTOP)
                return process, output
            if process.poll() is not None:
                self.fail('Export finished before interruption could be exercised')
            time.sleep(0.001)
        self.fail('Export did not reach staging within 15 seconds')

    def test_source_mutation_aborts_without_publishing(self):
        process, output = self.pause_export()
        (self.source / 'empty').write_bytes(b'changed after snapshot')
        process.send_signal(signal.SIGCONT)
        _, error = process.communicate(timeout=30)
        self.assertNotEqual(process.returncode, 0, error)
        self.assertIn('changed', error)
        self.assertFalse(output.exists())
        self.assertFalse(list(self.work.glob('repository-*.sql')))

    def test_sigint_and_sigterm_cleanup_staging(self):
        for signum in [signal.SIGINT, signal.SIGTERM]:
            with self.subTest(signal=signum):
                process, output = self.pause_export()
                process.send_signal(signum)
                process.send_signal(signal.SIGCONT)
                process.communicate(timeout=30)
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse(output.exists())
                self.assertFalse(list(self.work.glob('repository-*.sql')))


@unittest.skipUnless(DSN, 'REPOSITORY_TEST_DSN is required for real PostgreSQL audit')
class DatabaseAudit(AuditFixture):
    @classmethod
    def setUpClass(cls):
        cls.dbname = 'repository_audit_' + uuid.uuid4().hex
        result = psql(DSN, f'CREATE DATABASE "{cls.dbname}" TEMPLATE template0 ENCODING \'UTF8\';')
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.dsn = DSN + ' dbname=' + cls.dbname
        result = psql(cls.dsn, 'CREATE TABLE public.audit_sentinel(value text); INSERT INTO public.audit_sentinel VALUES (\'unchanged\');')
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        result = psql(cls.dsn, 'SELECT value FROM public.audit_sentinel;')
        if result.stdout.strip() != 'unchanged':
            raise AssertionError('Existing database data changed')
        result = psql(DSN, f'DROP DATABASE "{cls.dbname}" WITH (FORCE);')
        if result.returncode:
            raise AssertionError(result.stderr)

    def setUp(self):
        super().setUp()
        self.schema = 'audit_' + uuid.uuid4().hex
        self.addCleanup(lambda: psql(self.dsn, f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE;'))

    def test_independent_round_trip_after_source_and_importer_removed(self):
        groups = self.source / 'src/groups.json'
        groups.write_bytes(b'\xef\xbb\xbf' + file_bytes(groups))
        tech = self.source / 'src/technologies/a.json'
        tech.write_bytes(file_bytes(tech).replace(b'"future": {', b'"precise": 0.1234567890123456789012345, "huge": 1e400, "future": {'))
        expected = source_snapshot(self.source)
        archive = self.archive(self.schema)
        shutil.rmtree(self.source)
        self.standalone.unlink()
        result = psql(self.dsn, archive=archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        verify_database(self, self.dsn, expected, self.schema)
        images = rows(self.dsn, f'''SELECT encode(e.content,'hex') AS payload FROM "{self.schema}".technology_icons i
                                    JOIN "{self.schema}".entries e ON e.path=i.file_path''')
        self.assertEqual(images, [dict(payload=bytes(range(256)).hex())])

    def test_repeat_import_and_existing_schema_are_untouched(self):
        archive = self.archive(self.schema)
        self.assertEqual(psql(self.dsn, archive=archive).returncode, 0)
        before = rows(self.dsn, f'SELECT * FROM "{self.schema}".snapshot')
        self.assertNotEqual(psql(self.dsn, archive=archive).returncode, 0)
        self.assertEqual(rows(self.dsn, f'SELECT * FROM "{self.schema}".snapshot'), before)
        self.assertEqual(rows(self.dsn, 'SELECT * FROM public.audit_sentinel'), [dict(value='unchanged')])

    def test_concurrent_imports_have_one_complete_winner(self):
        expected = source_snapshot(self.source)
        archive = self.archive(self.schema)
        archive.write_text(archive.read_text().replace('CREATE SCHEMA', 'SELECT pg_sleep(0.2);\nCREATE SCHEMA', 1))
        args = ['psql', '-X', '-w', '--set=ON_ERROR_STOP=1', '--dbname', self.dsn, '--file', str(archive)]
        processes = [subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for process in processes:
            process.communicate(timeout=30)
        self.assertEqual(sum(p.returncode == 0 for p in processes), 1)
        verify_database(self, self.dsn, expected, self.schema)

    def test_corruption_and_truncation_roll_back_everything(self):
        archive = self.archive(self.schema)
        text = archive.read_text()
        copying = False
        lines = text.split('\n')
        selected = None
        for index, line in enumerate(lines):
            if line.startswith('COPY entries '):
                copying = True
            elif copying and line == r'\.':
                break
            elif copying and line.startswith('all-bytes.bin\t'):
                selected = index
        self.assertIsNotNone(selected)
        original = lines[selected].split('\t')
        for column, replacement in [(0, 'renamed.bin'), (1, 'missing-parent'), (2, r'\\x00'),
                                    (3, 'symlink'), (4, original[4].replace('"st_uid":', '"changed_uid":')),
                                    (5, 'changed/type'), (6, 'changed-target'), (7, r'\\x00'),
                                    (8, '0' * 64), (9, '0' * 64)]:
            with self.subTest(column=column):
                changed = original.copy()
                changed[column] = replacement
                corrupt = lines.copy()
                corrupt[selected] = '\t'.join(changed)
                result = psql(self.dsn, '\n'.join(corrupt))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(rows(self.dsn, f"SELECT nspname FROM pg_namespace WHERE nspname='{self.schema}'"), [])
        for prefix in [text[:len(text)//2], text[:text.index('COMMIT;')],
                       text.replace('"manifest_sha256": "', '"manifest_sha256": "corrupt-')]:
            result = psql(self.dsn, prefix)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(rows(self.dsn, f"SELECT nspname FROM pg_namespace WHERE nspname='{self.schema}'"), [])
        self.assertEqual(rows(self.dsn, 'SELECT * FROM public.audit_sentinel'), [dict(value='unchanged')])

    def test_direct_import_and_failure_messages(self):
        expected = source_snapshot(self.source)
        result = self.cli('--database', self.dsn, '--schema', self.schema)
        self.assertEqual(result.returncode, 0, result.stderr)
        verify_database(self, self.dsn, expected, self.schema)
        result = self.cli('--database', self.dsn, '--schema', self.schema)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('was rolled back', result.stderr)
        missing = self.cli('--database', self.dsn + ' dbname=does_not_exist')
        self.assertNotEqual(missing.returncode, 0)
        readonly = self.cli('--database', self.dsn, '--schema', self.schema + '_readonly',
                            env=dict(os.environ, PGOPTIONS='-c default_transaction_read_only=on'))
        self.assertNotEqual(readonly.returncode, 0)
        self.assertIn('read-only', readonly.stderr)

    def test_new_schema_preserves_existing_database_objects(self):
        result = self.cli('--database', self.dsn, '--schema', self.schema)
        self.assertEqual(result.returncode, 0, result.stderr)
        second = self.schema + '_two'
        self.addCleanup(lambda: psql(self.dsn, f'DROP SCHEMA IF EXISTS "{second}" CASCADE;'))
        result = self.cli('--database', self.dsn, '--schema', second)
        self.assertEqual(result.returncode, 0, result.stderr)
        first = rows(self.dsn, f'SELECT path,sha256 FROM "{self.schema}".entries ORDER BY path')
        self.assertEqual(first, rows(self.dsn, f'SELECT path,sha256 FROM "{second}".entries ORDER BY path'))
        self.assertEqual(rows(self.dsn, 'SELECT * FROM public.audit_sentinel'), [dict(value='unchanged')])

    def test_non_utf8_database_and_insufficient_privileges(self):
        other = self.dbname + '_ascii'
        self.assertEqual(psql(DSN, f'CREATE DATABASE "{other}" TEMPLATE template0 ENCODING \'SQL_ASCII\';').returncode, 0)
        try:
            result = self.cli('--database', DSN + ' dbname=' + other, '--schema', self.schema)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('UTF8', result.stderr)
        finally:
            psql(DSN, f'DROP DATABASE "{other}" WITH (FORCE);')
        role = 'audit_restricted_' + uuid.uuid4().hex
        self.assertEqual(psql(DSN, f'CREATE ROLE "{role}" LOGIN;').returncode, 0)
        try:
            result = self.cli('--database', self.dsn + ' user=' + role, '--schema', self.schema)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('permission denied', result.stderr)
            self.assertEqual(rows(self.dsn, f"SELECT nspname FROM pg_namespace WHERE nspname='{self.schema}'"), [])
        finally:
            psql(DSN, f'DROP ROLE "{role}";')

    def test_importer_signals_kill_child_and_leave_no_partial_schema(self):
        trigger = 'pause_' + uuid.uuid4().hex
        setup = f'''CREATE FUNCTION public.{trigger}() RETURNS event_trigger LANGUAGE plpgsql AS $$
                    BEGIN PERFORM pg_sleep(60); END $$;
                    CREATE EVENT TRIGGER {trigger} ON ddl_command_end WHEN TAG IN ('CREATE INDEX')
                    EXECUTE FUNCTION public.{trigger}();'''
        self.assertEqual(psql(self.dsn, setup).returncode, 0)
        try:
            signals = [signal.SIGINT, signal.SIGTERM]
            if sys.platform.startswith('linux'):
                signals.append(signal.SIGKILL)
            for signum in signals:
                with self.subTest(signal=signum):
                    appname = 'parent_interrupt_' + uuid.uuid4().hex
                    env = dict(os.environ, TMPDIR=str(self.work), PGAPPNAME=appname,
                               PGOPTIONS='-c client_connection_check_interval=100ms')
                    process = subprocess.Popen([sys.executable, '-B', str(self.standalone), str(self.source),
                                                '--database', self.dsn, '--schema', self.schema],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
                    try:
                        deadline = time.monotonic() + 15
                        while time.monotonic() < deadline:
                            active = rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}' AND wait_event='PgSleep'")
                            if active:
                                break
                            if process.poll() is not None:
                                self.fail('Importer exited before reaching pre-commit pause')
                            time.sleep(0.02)
                        else:
                            self.fail('Importer never reached pre-commit pause')
                        process.send_signal(signum)
                        process.communicate(timeout=10)
                        self.assertNotEqual(process.returncode, 0)
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline and rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}'"):
                            time.sleep(0.02)
                        self.assertEqual(rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}'"), [])
                        self.assertEqual(rows(self.dsn, f"SELECT nspname FROM pg_namespace WHERE nspname='{self.schema}'"), [])
                        staging = list(self.work.glob('repository-*.sql'))
                        if signum != signal.SIGKILL:
                            self.assertEqual(staging, [])
                        for path in staging:
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                            path.unlink()
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=10)
        finally:
            psql(self.dsn, f'DROP EVENT TRIGGER {trigger}; DROP FUNCTION public.{trigger}();')

    def test_interrupt_sql_transaction(self):
        archive = self.archive(self.schema)
        interrupted = self.work / 'pause.sql'
        interrupted.write_text(archive.read_text().replace('COMMIT;', "SET client_connection_check_interval='100ms';\nSELECT pg_sleep(60);\nCOMMIT;"))
        appname = 'interrupt_' + uuid.uuid4().hex
        process = subprocess.Popen(['psql', '-X', '-w', '--set=ON_ERROR_STOP=1', '--dbname', self.dsn,
                                    '--file', str(interrupted)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=dict(os.environ, PGAPPNAME=appname))
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                active = rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}' AND wait_event='PgSleep'")
                if active:
                    break
                time.sleep(0.02)
            else:
                self.fail('Import did not reach the pre-commit pause')
            self.assertEqual(rows(self.dsn, f"SELECT nspname FROM pg_namespace WHERE nspname='{self.schema}'"), [])
            process.send_signal(signal.SIGKILL)
            process.communicate(timeout=10)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}'"):
                time.sleep(0.02)
            self.assertEqual(rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}'"), [])
            self.assertEqual(rows(self.dsn, f"SELECT nspname FROM pg_namespace WHERE nspname='{self.schema}'"), [])
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    def test_disconnect_after_commit_does_not_undo_complete_import(self):
        expected = source_snapshot(self.source)
        archive = self.archive(self.schema)
        archive.write_text(archive.read_text().replace('COMMIT;', "COMMIT;\nSET client_connection_check_interval='100ms';\nSELECT pg_sleep(60);"))
        appname = 'after_commit_' + uuid.uuid4().hex
        process = subprocess.Popen(['psql', '-X', '-w', '--set=ON_ERROR_STOP=1', '--dbname', self.dsn,
                                    '--file', str(archive)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=dict(os.environ, PGAPPNAME=appname))
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if rows(self.dsn, f"SELECT pid FROM pg_stat_activity WHERE application_name='{appname}' AND wait_event='PgSleep'"):
                    break
                time.sleep(0.02)
            else:
                self.fail('Import did not reach the post-commit pause')
            process.kill()
            process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            verify_database(self, self.dsn, expected, self.schema)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    @unittest.skipUnless(os.environ.get('REPOSITORY_AUDIT_SOURCE'), 'Set REPOSITORY_AUDIT_SOURCE for full checkout verification')
    def test_full_checkout_archive_only_in_fresh_database(self):
        self.schema = 'webappanalyzer'
        source = Path(os.environ['REPOSITORY_AUDIT_SOURCE']).resolve()
        expected = source_snapshot(source)
        archive = self.work / 'full.sql'
        result = subprocess.run([sys.executable, '-B', str(self.standalone), str(source), '--output', str(archive),
                                 '--schema', self.schema], text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.standalone.unlink()
        container = os.environ.get('REPOSITORY_TEST_CONTAINER')
        if container:
            subprocess.run(['docker', 'cp', str(archive), container + ':/tmp/repository.sql'], check=True, capture_output=True)
            denied = subprocess.run(['docker', 'exec', container, 'test', '!', '-e', str(source)], capture_output=True)
            self.assertEqual(denied.returncode, 0, 'Repository must not exist in restore container')
            result = subprocess.run(['docker', 'exec', container, 'psql', '-X', '-w', '-h', '/socket', '-U', 'postgres',
                                     '--set=ON_ERROR_STOP=1', '--dbname', self.dbname, '--file', '/tmp/repository.sql'],
                                    capture_output=True, text=True, timeout=120)
        else:
            result = psql(self.dsn, archive=archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = verify_database(self, self.dsn, expected, self.schema)
        second_db = self.dbname + '_restore'
        self.assertEqual(psql(DSN, f'CREATE DATABASE "{second_db}" TEMPLATE template0 ENCODING \'UTF8\';').returncode, 0)
        try:
            second_dsn = DSN + ' dbname=' + second_db
            if container:
                result = subprocess.run(['docker', 'exec', container, 'psql', '-X', '-w', '-h', '/socket', '-U', 'postgres',
                                         '--set=ON_ERROR_STOP=1', '--dbname', second_db, '--file', '/tmp/repository.sql'],
                                        capture_output=True, text=True, timeout=120)
            else:
                result = psql(second_dsn, archive=archive)
            self.assertEqual(result.returncode, 0, result.stderr)
            second_report = verify_database(self, second_dsn, expected, self.schema)
            self.assertEqual(second_report, report, 'Same archive must recreate identical snapshot metadata and data')
        finally:
            psql(DSN, f'DROP DATABASE "{second_db}" WITH (FORCE);')
        result_dir = os.environ.get('REPOSITORY_AUDIT_RESULTS')
        if result_dir:
            output = Path(result_dir)
            output.mkdir(parents=True, exist_ok=True)
            version = rows(self.dsn, 'SELECT version() AS version')[0]['version']
            label = version.split()[1]
            saved_archive = output / f'verified-postgres-{label}.sql'
            shutil.copyfile(archive, saved_archive)
            saved_archive.chmod(0o600)
            (output / f'verified-postgres-{label}.json').write_text(json.dumps(
                dict(report, server_version=version, repository_unavailable_in_container=bool(container),
                     archive_restorations=2, additional_empty_database_restorations=1), indent=2))


if __name__ == '__main__':
    unittest.main()
