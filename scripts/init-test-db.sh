#!/bin/sh
# Creates the test database alongside the development one. Run once by the
# Postgres image's entrypoint on first start.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
  CREATE DATABASE zentra_test OWNER $POSTGRES_USER;
SQL
