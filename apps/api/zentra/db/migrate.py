"""Forward-only SQL migration runner.

Applies the ordered `.sql` files in ``supabase/migrations`` and records each in
a ``schema_migrations`` table. The same files are what ``supabase db push``
applies to hosted Supabase, so local and production schemas cannot drift.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

from sqlalchemy import text

from zentra.config import get_settings
from zentra.db.session import engine_for
from zentra.logging import get_logger

log = get_logger("zentra.migrate")

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[4] / "supabase" / "migrations"

_BOOTSTRAP = """
create table if not exists public.schema_migrations (
  version    text primary key,
  checksum   text not null,
  applied_at timestamptz not null default now()
)
"""


def discover(directory: pathlib.Path | None = None) -> list[pathlib.Path]:
    directory = directory or MIGRATIONS_DIR
    if not directory.exists():
        raise FileNotFoundError(f"Migrations directory not found: {directory}")
    return sorted(p for p in directory.glob("*.sql") if not p.name.startswith("_"))


def run_migrations(database_url: str | None = None, directory: pathlib.Path | None = None) -> int:
    settings = get_settings()
    url = database_url or settings.effective_database_url
    engine = engine_for(url)
    applied = 0
    with engine.begin() as conn:
        conn.execute(text(_BOOTSTRAP))
        rows = conn.execute(text("select version, checksum from public.schema_migrations")).all()
        known = {r[0]: r[1] for r in rows}

    for path in discover(directory):
        version = path.stem
        body = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(body.encode()).hexdigest()
        if version in known:
            if known[version] != checksum:
                raise RuntimeError(
                    f"Migration {version} has changed after being applied. "
                    "Create a new migration instead of editing an applied one."
                )
            continue
        log.info("migration_applying", version=version)
        with engine.begin() as conn:
            # Use the raw DBAPI cursor: psycopg3 would otherwise try to parse
            # `%` and `$1`-style tokens inside the SQL as bind placeholders.
            raw = conn.connection.dbapi_connection
            with raw.cursor() as cur:  # type: ignore[union-attr]
                cur.execute(body)
            conn.execute(
                text("insert into public.schema_migrations (version, checksum) values (:v, :c)"),
                {"v": version, "c": checksum},
            )
        applied += 1
        log.info("migration_applied", version=version)

    if applied == 0:
        log.info("migrations_up_to_date")
    return applied


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else None
    count = run_migrations(url)
    print(f"Applied {count} migration(s).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
