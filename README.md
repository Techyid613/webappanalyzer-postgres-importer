# Webappanalyzer to PostgreSQL

Importer for the upstream [Webappanalyzer repository](https://github.com/enthec/webappanalyzer).

A standalone, standard-library Python importer that archives a local Webappanalyzer checkout and loads its complete local contents into PostgreSQL. The SQL archive embeds file and image bytes, so restoring it does not require the original checkout or this importer.

## Requirements

- Python 3.10+
- PostgreSQL 14+ with a UTF8 database
- `psql` for direct database imports

## Use

Create a self-contained SQL archive outside the source checkout, then restore it:

```bash
python3 scripts/repository_to_postgres.py /path/to/webappanalyzer \
  --output /tmp/webappanalyzer.sql
createdb webappanalyzer
psql -X --set=ON_ERROR_STOP=1 --dbname webappanalyzer \
  --file /tmp/webappanalyzer.sql
```

Or import directly into an existing database (the importer creates a new schema):

```bash
python3 scripts/repository_to_postgres.py /path/to/webappanalyzer \
  --database webappanalyzer
```

See [the detailed guide](scripts/repository_to_postgres.md) for the schema, SQL examples, integrity checks, operational limits, and tests. The guide explains exactly which local files and metadata are preserved and which remote or unavailable content cannot be included.

## Tests

Run the fast unit and fixture suite:

```bash
python3 -B -m unittest discover -s scripts -p 'test_repository_to_postgres*.py'
```

Set `REPOSITORY_TEST_DSN` to run the PostgreSQL integration tests against a disposable database. Set `REPOSITORY_AUDIT_SOURCE` as well to independently compare a full source checkout with restored database contents. See the guide for configuration and safety details.

## License

This project is distributed under [GNU GPL-3.0](LICENSE), matching the source repository license.
