# Repository to PostgreSQL

`repository_to_postgres.py` is a standalone Python 3.10+ script for this
repository's data layout. It uses the standard library and a UTF8 PostgreSQL 14+
database. Python 3.12 and PostgreSQL 16/17 are exercised by the audit suite.
Run it on a quiet checkout. It creates a new schema in an existing database;
it does not replace schemas, databases, output files, or source files.

Generate a portable, self-contained SQL archive **outside the checkout**:

```bash
python3 scripts/repository_to_postgres.py . --output /tmp/webappanalyzer.sql
createdb webappanalyzer
psql -X --set=ON_ERROR_STOP=1 --dbname webappanalyzer --file /tmp/webappanalyzer.sql
```

The Python script is not needed to load that SQL file. PostgreSQL does not need
access to the repository or filesystem: all payloads are inline `COPY FROM STDIN`
data. No extensions, network downloads, or server-side file access are required.

Alternatively, import directly with `psql` installed:

```bash
python3 scripts/repository_to_postgres.py /path/to/checkout --database webappanalyzer
```

Use the standard `PGHOST`, `PGPORT`, `PGUSER`, `PGSERVICE`, and `.pgpass` connection
settings. Avoid putting passwords in command arguments. `--schema another_name`
imports an additional snapshot without changing an existing one. SQL output files
are created with private permissions because they include every local file.

## What is preserved

- Every directory and regular file under the source, without ignore rules:
  technologies, categories, groups, all images (including unreferenced ones),
  documentation, license, configuration, scripts, hidden files, ignored files,
  and the entire local `.git` directory. The importer itself is included if it
  resides in the checkout at export time.
- Exact binary bytes, relative paths and path bytes, per-file SHA-256, MIME hints,
  all `os.stat` fields available on the host (including permission bits, IDs,
  inode/device, link count, and nanosecond timestamps), and readable extended
  attributes as hex. Hardlink identity is retained through device/inode metadata.
  `metadata_json` retains the exact serialized metadata; `metadata` is its
  generated JSONB representation. Entry digests bind paths, parent paths, path
  bytes, kinds, metadata, MIME hints, symlink destinations and payload hashes.
- Internal symlink targets as exact bytes, plus their resolved relative paths.
  Symlinks are not followed during directory traversal. Empty files and empty
  directories are included.
- Every JSON field and nested value in technology, category, and group records.
  PostgreSQL parses the original JSON bytes directly, preserving numeric precision.
  Raw file bytes retain whitespace, key order, original encoding, and escaping.
- Ordered category/group links, technology/category links, `requiresCategory`,
  `implies`, `requires`, `excludes`, raw relationship strings and ordered tags,
  and icon references. Icon references through internal symlinks resolve to the
  actual stored image file; the original symlink remains archived in `entries`.
  Repeated links remain separate rows. Missing targets remain
  in the raw records and link tables, with nullable resolved foreign keys and an
  `unresolved_references` view; they are never silently dropped or invented.

## Database layout

All objects are in `webappanalyzer` unless `--schema` is specified.

| Object | Contents |
| --- | --- |
| `snapshot` | Version, export time, inventory counts, payload size, manifest hash, source metadata |
| `entries` | File/directory/symlink archive, exact metadata JSON, generated metadata JSONB, byte payloads and entry/content checksums |
| `groups`, `categories`, `technologies` | Full JSONB definitions and source-file foreign keys |
| `category_groups` | Ordered category-to-group links |
| `technology_categories` | Ordered `cats` and `requiresCategory` links |
| `technology_relationships` | Ordered technology links, raw values, targets and tags |
| `technology_icons` | Technology-to-asset foreign keys and original icon names |
| `technology_fields` | View of every technology field, including all detection patterns |
| `assets` | View of all files under `src/images/`, with payloads |
| `unresolved_references` | View of missing relationship/icon targets |

Examples:

```sql
SELECT name, definition->>'website', definition->'dom'
FROM webappanalyzer.technologies WHERE name = 'WordPress';

SELECT * FROM webappanalyzer.technology_relationships
WHERE technology_name = 'WordPress' ORDER BY kind, position;

SELECT i.technology_name, e.media_type, e.content, e.sha256
FROM webappanalyzer.technology_icons i
JOIN webappanalyzer.entries e ON e.path = i.file_path
WHERE i.technology_name = 'WordPress';

-- Export a payload to the client without the original repository:
SELECT encode(content, 'base64')
FROM webappanalyzer.entries WHERE path = 'LICENSE';

SELECT * FROM webappanalyzer.unresolved_references;
```

After import, `pg_dump --dbname webappanalyzer > backup.sql` creates a backup
that is also independent of the repository and the importer.

## Integrity and boundaries

Generation checks for duplicate JSON keys and cross-file technology names,
PostgreSQL-incompatible JSON values, malformed relationship arrays, unreadable
entries, unsupported file types, and source changes. Structured source JSON must
be UTF8 (an initial UTF8 BOM is supported) and reside in regular files. Arbitrary
other files are archived as bytes regardless of encoding. Opened file identities
are checked before and after reading; nonblocking opens prevent a file-to-FIFO
race from hanging the exporter.

Output publication uses an exclusive hardlink only after a complete export, then
fsyncs the output directory. Import uses one transaction, stop-on-error behavior,
content-length/SHA-256 constraints, per-entry digests, foreign keys, and a final
ordered manifest digest plus inventory/size/kind checks. Snapshot export time is
embedded in the archive, so repeated restores of the same archive retain it.
Archive format version 2 adds these checks; previous archives are not upgraded.

An existing schema fails without changing it. Failures **before commit** roll
back; a connection failure at commit can have an uncertain outcome, so inspect
the destination before retrying. The success message is printed after commit.
An unclosed psql conditional guard makes truncation after the header return an
error, including EOF before commit. An empty file or truncation before the guard
cannot be recognized as an incomplete archive by psql itself; retain/verify the
archive checksum when transferring it.

SIGINT/SIGTERM clean up staging files and terminate a running child psql process.
On Linux, the child also receives a parent-death signal if the importer is killed
with SIGKILL. SIGKILL can leave a private `repository-*.sql` staging file behind;
inspect and remove it after checking the destination. On other POSIX systems,
SIGKILL may leave a child psql running. Server rollback may be delayed until it
detects the disconnected client. An import killed after commit can already be
complete; signals do not undo committed transactions.

This is a snapshot of **locally present contents**, not a download of everything
mentioned by a URL. This checkout is shallow: its absent upstream Git history is
not available to archive. Unfetched submodules, Git LFS objects, and remote web
pages are not local payloads. External symlinks and linked/alternate Git storage
are rejected instead of producing a snapshot dependent on outside files.

The script targets POSIX filesystems with extended-attribute APIs. It fails
explicitly on non-UTF-8 path names, special files (e.g. sockets/FIFOs/devices),
permission failures, or files larger than 256 MiB. This bound keeps hex COPY rows
below PostgreSQL's text-input limits; larger files require a chunked format.
File/directory reads use no-atime mode where permitted; filesystem reads and
readlink calls can otherwise update access times. Source file bytes, permissions,
and modification times are never written.
Creation/status-change times and owner IDs are stored as metadata; recreating
them on another filesystem may require privileges or be impossible on that OS.
SQL archives hex-encode binary data and require roughly twice the payload space;
generation memory use scales with the largest file. Keep the source quiet until
generation finishes; live filesystem scans cannot provide filesystem-level
atomic snapshots. SHA-256 checks detect accidental corruption; they do not
authenticate an archive against an attacker who can replace SQL and checksums.

## Checks

```bash
python3 -B -m unittest discover -s scripts -p 'test_repository_to_postgres*.py'

# Real integration tests; disposable server/role must allow CREATE DATABASE:
REPOSITORY_TEST_DSN='dbname=disposable_test_db' \
  python3 -B -m unittest discover -s scripts -p 'test_repository_to_postgres*.py'

# Also compare every file/metadata field/record/link in the whole checkout:
REPOSITORY_TEST_DSN='dbname=disposable_test_db' \
REPOSITORY_AUDIT_SOURCE="$PWD" \
REPOSITORY_AUDIT_RESULTS=/tmp/repository-audit-results \
  python3 -B -m unittest discover -s scripts -p 'test_repository_to_postgres*.py'
```

`test_repository_to_postgres_audit.py` does not import the exporter. It independently
scans source bytes, all available stat/xattr fields, JSON definitions, and all
ordered links/tags, then compares them with database rows. It tests deleted-source
fixture restoration, existing/concurrent/repeat imports, failures, corruption,
truncation and real process signals. The optional full-checkout test restores
the same archive into an existing disposable test database and an additional
empty, freshly created database, comparing both independently.

For a container without a repository mount, set `REPOSITORY_TEST_CONTAINER` to
its Docker name. The full-checkout test copies only the SQL archive into it and
runs psql there through `/socket` as `postgres`, proving that the restore client
and server can operate without the checkout or Python importer. Use a local,
network-isolated disposable container, not a production database.
