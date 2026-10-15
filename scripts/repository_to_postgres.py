#!/usr/bin/env python3
"""Archive a webappanalyzer checkout and index its data in PostgreSQL.

Python 3.10+, standard library only; PostgreSQL 14+ (psql for --database).
Examples:
  python3 repository_to_postgres.py /path/to/checkout --output /tmp/repository.sql
  python3 repository_to_postgres.py /path/to/checkout --database my_database

Every local file, including hidden/ignored files and .git, is included. Outputs
must be outside the source. Existing schemas and output files are never replaced.
See repository_to_postgres.md for the schema, queries, and preservation limits.
"""

import argparse
import ctypes
from decimal import Decimal
from datetime import datetime, timezone
import errno
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

MAX_FILE_BYTES = 256 * 1024 * 1024


DDL = r"""
\set ON_ERROR_STOP on
\if true
BEGIN;
SET LOCAL client_encoding = 'UTF8';
DO $requirements$
BEGIN
    IF current_setting('server_encoding') <> 'UTF8'
       OR current_setting('server_version_num')::integer < 140000 THEN
        RAISE EXCEPTION 'Requires PostgreSQL 14+ and a UTF8 database';
    END IF;
END
$requirements$;
CREATE SCHEMA "{schema}";
SET LOCAL search_path = "{schema}", pg_catalog;
CREATE FUNCTION entry_digest(VARIADIC fields bytea[]) RETURNS text
LANGUAGE sql IMMUTABLE AS $digest$
    SELECT encode(sha256(convert_to(string_agg(
        coalesce(encode(sha256(value), 'hex'), '-'), ':' ORDER BY position
    ), 'UTF8')), 'hex') FROM unnest(fields) WITH ORDINALITY AS item(value, position)
$digest$;
CREATE TABLE snapshot (
    format_version integer PRIMARY KEY CHECK (format_version = 2),
    exported_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    manifest jsonb NOT NULL
);
CREATE TABLE entries (
    path text COLLATE "C" PRIMARY KEY,
    parent_path text REFERENCES entries(path) DEFERRABLE INITIALLY DEFERRED,
    path_bytes bytea NOT NULL UNIQUE,
    kind text NOT NULL CHECK (kind IN ('file', 'directory', 'symlink')),
    metadata_json text NOT NULL,
    metadata jsonb GENERATED ALWAYS AS (metadata_json::jsonb) STORED,
    media_type text,
    link_path text,
    content bytea,
    sha256 text,
    entry_sha256 text NOT NULL CHECK (entry_sha256 = entry_digest(
        convert_to(path, 'UTF8'), convert_to(parent_path, 'UTF8'), path_bytes,
        convert_to(kind, 'UTF8'), convert_to(metadata_json, 'UTF8'),
        convert_to(media_type, 'UTF8'), convert_to(link_path, 'UTF8'),
        convert_to(sha256, 'UTF8')
    )),
    CHECK (
        (kind = 'directory' AND content IS NULL AND sha256 IS NULL) OR
        (kind IN ('file', 'symlink') AND content IS NOT NULL AND sha256 IS NOT NULL
         AND octet_length(content) = (metadata->>'st_size')::bigint
         AND encode(sha256(content), 'hex') = sha256)
    )
);
CREATE TABLE groups (
    id text COLLATE "C" PRIMARY KEY,
    source_path text NOT NULL REFERENCES entries(path),
    definition jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object')
);
CREATE TABLE categories (LIKE groups INCLUDING ALL);
ALTER TABLE categories ADD FOREIGN KEY (source_path) REFERENCES entries(path);
CREATE TABLE technologies (
    name text COLLATE "C" PRIMARY KEY,
    source_path text NOT NULL REFERENCES entries(path),
    definition jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object')
);
CREATE TABLE category_groups (
    category_id text NOT NULL REFERENCES categories(id),
    position bigint NOT NULL,
    group_id text NOT NULL,
    resolved_group_id text REFERENCES groups(id),
    PRIMARY KEY (category_id, position)
);
CREATE TABLE technology_categories (
    technology_name text NOT NULL REFERENCES technologies(name),
    kind text NOT NULL CHECK (kind IN ('cats', 'requiresCategory')),
    position bigint NOT NULL,
    category_id text NOT NULL,
    resolved_category_id text REFERENCES categories(id),
    PRIMARY KEY (technology_name, kind, position)
);
CREATE TABLE technology_relationships (
    technology_name text NOT NULL REFERENCES technologies(name),
    kind text NOT NULL CHECK (kind IN ('implies', 'requires', 'excludes')),
    position bigint NOT NULL,
    raw_value text NOT NULL,
    target_name text NOT NULL,
    tags jsonb NOT NULL,
    resolved_target_name text REFERENCES technologies(name),
    PRIMARY KEY (technology_name, kind, position)
);
CREATE TABLE technology_icons (
    technology_name text COLLATE "C" PRIMARY KEY REFERENCES technologies(name),
    icon_name text NOT NULL,
    file_path text COLLATE "C" REFERENCES entries(path)
);
"""

INDEX_DATA = r"""
INSERT INTO groups
SELECT j.key, e.path, j.value FROM entries e
CROSS JOIN LATERAL jsonb_each(ltrim(convert_from(e.content, 'UTF8'), chr(65279))::jsonb) j
WHERE e.path = 'src/groups.json';
INSERT INTO categories
SELECT j.key, e.path, j.value FROM entries e
CROSS JOIN LATERAL jsonb_each(ltrim(convert_from(e.content, 'UTF8'), chr(65279))::jsonb) j
WHERE e.path = 'src/categories.json';
INSERT INTO technologies
SELECT j.key, e.path, j.value FROM entries e
CROSS JOIN LATERAL jsonb_each(ltrim(convert_from(e.content, 'UTF8'), chr(65279))::jsonb) j
WHERE e.parent_path = 'src/technologies' AND right(e.path, 5) = '.json';

INSERT INTO category_groups
SELECT c.id, r.position, r.value, g.id
FROM categories c
CROSS JOIN LATERAL jsonb_array_elements_text(c.definition->'groups')
    WITH ORDINALITY r(value, position)
LEFT JOIN groups g ON g.id = r.value;
INSERT INTO technology_categories
SELECT t.name, k.kind, r.position, r.value, c.id
FROM technologies t CROSS JOIN (VALUES ('cats'), ('requiresCategory')) k(kind)
CROSS JOIN LATERAL jsonb_array_elements_text(t.definition->k.kind)
    WITH ORDINALITY r(value, position)
LEFT JOIN categories c ON c.id = r.value;
INSERT INTO technology_relationships
SELECT t.name, k.kind, r.position, r.value,
    split_part(r.value, chr(92) || ';', 1),
    to_jsonb((string_to_array(r.value, chr(92) || ';'))[2:]), target.name
FROM technologies t CROSS JOIN (VALUES ('implies'), ('requires'), ('excludes')) k(kind)
CROSS JOIN LATERAL jsonb_array_elements_text(t.definition->k.kind)
    WITH ORDINALITY r(value, position)
LEFT JOIN technologies target ON target.name = split_part(r.value, chr(92) || ';', 1);
INSERT INTO technology_icons
SELECT t.name, t.definition->>'icon', payload.path
FROM technologies t LEFT JOIN entries e
    ON e.path = 'src/images/icons/' || (t.definition->>'icon')
       AND e.kind IN ('file', 'symlink')
LEFT JOIN entries payload ON payload.kind = 'file'
    AND payload.path = CASE WHEN e.kind = 'symlink' THEN e.link_path ELSE e.path END
WHERE t.definition ? 'icon';

CREATE INDEX ON technologies USING gin (definition);
CREATE VIEW technology_fields AS
SELECT t.name AS technology_name, f.key AS field, f.value
FROM technologies t CROSS JOIN LATERAL jsonb_each(t.definition) f;
CREATE VIEW assets AS
SELECT * FROM entries WHERE kind = 'file' AND path LIKE 'src/images/%';
CREATE VIEW unresolved_references AS
SELECT category_id AS source, 'groups'::text AS kind, group_id AS target
FROM category_groups WHERE resolved_group_id IS NULL
UNION ALL
SELECT technology_name, kind, category_id FROM technology_categories
WHERE resolved_category_id IS NULL
UNION ALL
SELECT technology_name, kind, target_name FROM technology_relationships
WHERE resolved_target_name IS NULL
UNION ALL
SELECT technology_name, 'icon', icon_name FROM technology_icons WHERE file_path IS NULL;

DO $verify$
BEGIN
    IF (SELECT count(*) FROM snapshot) <> 1
    OR (SELECT count(*) FROM entries) IS DISTINCT FROM
       (SELECT (manifest->>'entry_count')::bigint FROM snapshot)
    OR (SELECT coalesce(sum(octet_length(content)), 0) FROM entries) IS DISTINCT FROM
       (SELECT (manifest->>'payload_bytes')::bigint FROM snapshot)
    OR (SELECT jsonb_build_object(
        'file', count(*) FILTER (WHERE kind = 'file'),
        'directory', count(*) FILTER (WHERE kind = 'directory'),
        'symlink', count(*) FILTER (WHERE kind = 'symlink')) FROM entries) IS DISTINCT FROM
       (SELECT manifest->'counts' FROM snapshot)
    OR (SELECT encode(sha256(convert_to(string_agg(entry_sha256, '' ORDER BY path COLLATE "C"), 'UTF8')), 'hex') FROM entries) IS DISTINCT FROM
       (SELECT manifest->>'manifest_sha256' FROM snapshot) THEN
        RAISE EXCEPTION 'Archive inventory mismatch';
    END IF;
END
$verify$;
COMMIT;
\endif
"""


def signature(info):
    """Ignore access time, which reading a file may update."""
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
        'st_size', 'st_mtime_ns', 'st_ctime_ns',
    ))


def inventory(root):
    result = {}

    def visit(path):
        info = path.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)):
            raise ValueError(f'Cannot archive special filesystem entry: {path}')
        relative = path.relative_to(root).as_posix()
        relative.encode('utf8')  # Fail rather than replace undecodable path bytes.
        result[relative] = info
        if stat.S_ISDIR(info.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
            try:
                fd = os.open(path, flags | getattr(os, 'O_NOATIME', 0))
            except PermissionError:
                fd = os.open(path, flags)
            try:
                if signature(os.fstat(fd)) != signature(info):
                    raise ValueError(f'Source directory changed: {path}')
                with os.scandir(fd) as children:
                    names = sorted((child.name for child in children), key=os.fsencode)
                for name in names:
                    visit(path / name)
            finally:
                os.close(fd)

    visit(root)
    return result


def read_bytes(path, expected=None):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags | getattr(os, 'O_NOATIME', 0))
    except PermissionError:
        fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (expected is not None and signature(opened) != signature(expected)):
            raise ValueError(f'Source changed before opening: {path}')
        content = stream.read()
        if signature(os.fstat(stream.fileno())) != signature(opened):
            raise ValueError(f'Source changed while reading: {path}')
        return content


def metadata(path, info):
    result = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
    try:
        result['xattrs_hex'] = {
            os.fsencode(key).hex(): os.getxattr(path, key, follow_symlinks=False).hex()
            for key in os.listxattr(path, follow_symlinks=False)
        }
    except OSError as error:
        if error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP):
            raise
        result['xattrs_hex'] = None
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON key: {key!r}')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f'Non-JSON numeric constant: {value}')


def validate_document(content, path):
    document = json.loads(content.decode('utf-8-sig'), object_pairs_hook=unique_object,
                          parse_float=Decimal, parse_int=Decimal, parse_constant=invalid_constant)

    def compatible(value):
        if isinstance(value, str):
            value.encode('utf8')
            if '\x00' in value:
                raise ValueError(f'PostgreSQL JSONB cannot store NUL characters: {path}')
        elif isinstance(value, Decimal):
            if value.adjusted() >= 131072 or -value.as_tuple().exponent > 16383:
                raise ValueError(f'Number exceeds PostgreSQL JSONB numeric limits: {path}')
        elif isinstance(value, dict):
            for key, item in value.items():
                compatible(key)
                compatible(item)
        elif isinstance(value, list):
            for item in value:
                compatible(item)

    compatible(document)
    if not isinstance(document, dict) or not all(isinstance(v, dict) for v in document.values()):
        raise ValueError(f'Expected a JSON object of records: {path}')
    for name, record in document.items():
        for field in ('groups', 'cats', 'requiresCategory', 'implies', 'requires', 'excludes'):
            if field not in record:
                continue
            allowed = (str,) if field in ('implies', 'requires', 'excludes') else (str, Decimal)
            if not isinstance(record[field], list) or any(not isinstance(v, allowed) for v in record[field]):
                raise ValueError(f'Invalid relationship array {name!r}.{field}: {path}')
        if 'icon' in record and not isinstance(record['icon'], str):
            raise ValueError(f'Invalid icon name for {name!r}: {path}')
    return document


def entry_digest(values):
    hashes = [b'-' if v is None else hashlib.sha256(
        v if isinstance(v, bytes) else v.encode('utf8')).hexdigest().encode('ascii') for v in values]
    return hashlib.sha256(b':'.join(hashes)).hexdigest()


def copy_value(value):
    if value is None:
        return r'\N'
    if isinstance(value, bytes):
        value = r'\x' + value.hex()
    return (str(value).replace('\\', '\\\\').replace('\t', '\\t')
            .replace('\n', '\\n').replace('\r', '\\r'))


def copy_row(stream, values):
    stream.write('\t'.join(copy_value(value) for value in values) + '\n')


def psql_parent_guard():
    """On Linux, terminate psql even if its Python parent is killed with SIGKILL."""
    if not sys.platform.startswith('linux'):
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    parent_pid = os.getpid()

    def guard():
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0):  # PR_SET_PDEATHSIG
            raise OSError(ctypes.get_errno(), 'Cannot set child parent-death signal')
        if os.getppid() != parent_pid:
            os.kill(os.getpid(), signal.SIGTERM)

    return guard


def export(root, stream, schema):
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', schema) or schema.startswith('pg_'):
        raise ValueError('Schema must be a lowercase SQL identifier, at most 63 characters, without pg_ prefix')
    before = inventory(root)
    required = {'src/groups.json', 'src/categories.json'}
    documents = required | {p for p in before if
        Path(p).parent.as_posix() == 'src/technologies' and p.endswith('.json')
    }
    if not required <= before.keys() or len(documents) == len(required):
        raise ValueError('Source must contain src/groups.json, src/categories.json, and technology JSON files')
    if any(not stat.S_ISREG(before[p].st_mode) for p in documents):
        raise ValueError('Structured JSON documents must be regular files, not directories or symlinks')
    stream.write(DDL.format(schema=schema))
    stream.write('COPY entries (path, parent_path, path_bytes, kind, metadata_json, media_type, link_path, content, sha256, entry_sha256) FROM STDIN;\n')
    digests = {}
    technology_names = set()
    counts = {'file': 0, 'directory': 0, 'symlink': 0}
    payload_bytes = 0
    for relative, info in before.items():
        path = root / relative
        link_path = None
        if stat.S_ISDIR(info.st_mode):
            kind, content = 'directory', None
        elif stat.S_ISLNK(info.st_mode):
            kind, content = 'symlink', os.fsencode(os.readlink(path))
            target = path.resolve(strict=False)
            if not target.is_relative_to(root):
                raise ValueError(f'External symlink would require outside files: {relative}')
            link_path = target.relative_to(root).as_posix()
        else:
            # shortcut: cap COPY hex rows at 512 MiB; use chunk storage for larger files.
            if info.st_size > MAX_FILE_BYTES:
                raise ValueError(f'File exceeds PostgreSQL bytea safety limit: {relative}')
            kind, content = 'file', read_bytes(path, info)
            if Path(relative).name == '.git' or ('.git' in Path(relative).parts and (
                Path(relative).name == 'commondir' or relative.endswith('/objects/info/alternates')
                or relative.endswith('/objects/info/http-alternates')
            ) and content.strip()):
                raise ValueError(f'External Git storage is unsupported; use a self-contained clone: {relative}')
            if relative in documents:
                document = validate_document(content, relative)
                if relative not in required:
                    if technology_names.intersection(document):
                        raise ValueError(f'Duplicate technology name across JSON files: {relative}')
                    technology_names.update(document)
        if signature(path.lstat()) != signature(info):
            raise ValueError(f'Source changed while reading: {relative}')
        details = json.dumps(metadata(path, info), ensure_ascii=True, sort_keys=True)
        checksum = hashlib.sha256(content).hexdigest() if content is not None else None
        parent = None if relative == '.' else Path(relative).parent.as_posix()
        media_type = mimetypes.guess_type(relative)[0] if kind == 'file' else None
        row_hash = entry_digest((relative, parent, os.fsencode(relative), kind, details, media_type, link_path, checksum))
        copy_row(stream, (relative, parent, os.fsencode(relative), kind, details,
                          media_type, link_path, content, checksum, row_hash))
        digests[relative] = row_hash
        counts[kind] += 1
        payload_bytes += len(content) if content is not None else 0
    stream.write('\\.\nCOPY snapshot (format_version, exported_at, manifest) FROM STDIN;\n')
    after = inventory(root)
    if {p: signature(s) for p, s in before.items()} != {p: signature(s) for p, s in after.items()}:
        raise ValueError('Source inventory changed during export; retry with a quiet checkout')
    manifest = dict(entry_count=len(before), payload_bytes=payload_bytes, counts=counts,
                    manifest_sha256=hashlib.sha256(''.join(digests[p] for p in sorted(digests)).encode('ascii')).hexdigest(), source_name=root.name,
                    source_path=str(root), git_shallow='.git/shallow' in before)
    copy_row(stream, (2, datetime.now(timezone.utc).isoformat(), json.dumps(manifest)))
    stream.write('\\.\n' + INDEX_DATA)
    stream.write(f'''SELECT 'Import complete' AS status,
        (SELECT count(*) FROM "{schema}".entries) AS entries,
        (SELECT count(*) FROM "{schema}".technologies) AS technologies,
        (SELECT count(*) FROM "{schema}".unresolved_references) AS unresolved_references;\n''')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('source', type=Path, help='Checkout to archive, including hidden and ignored files')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--output', type=Path, help='New self-contained psql SQL file, outside the source')
    target.add_argument('--database', help='Existing PostgreSQL database or connection string; uses psql and PG* environment')
    parser.add_argument('--schema', default='webappanalyzer', help='New schema name (default: webappanalyzer)')
    args = parser.parse_args()
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        root = args.source.resolve(strict=True)
        output = args.output.absolute() if args.output else None
        if output and output.resolve().is_relative_to(root):
            raise ValueError('Output must be outside the source to avoid archiving the output itself')
        if output and output.exists():
            raise FileExistsError('Output already exists; choose a new filename')
        if args.database and not shutil.which('psql'):
            raise ValueError('psql is required for --database; use --output to export without it')
        with tempfile.NamedTemporaryFile(mode='w+', encoding='utf8', newline='\n',
                                         dir=output.parent if output else None,
                                         prefix='repository-', suffix='.sql') as stream:
            if Path(stream.name).resolve().is_relative_to(root):
                raise ValueError('Temporary files must be outside the source; set TMPDIR elsewhere')
            manifest = export(root, stream, args.schema)
            stream.flush()
            os.fsync(stream.fileno())
            if output:
                os.link(stream.name, output)  # Publish only a complete file, without overwriting.
                directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            else:
                subprocess.run(['psql', '-X', '--set=ON_ERROR_STOP=1', '--dbname', args.database,
                                '--file', stream.name], check=True, preexec_fn=psql_parent_guard())
        print(json.dumps(manifest, indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        # Connection errors may contain credentials; psql reports its own diagnostics.
        message = 'psql failed; check database state before retrying because commit may have completed' if isinstance(error, subprocess.SubprocessError) else str(error)
        parser.exit(1, f'Error: {message}\n')
    except KeyboardInterrupt:
        parser.exit(130, 'Interrupted; check database state before retrying\n')


if __name__ == '__main__':
    main()
