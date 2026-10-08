# PostgreSQL migrations

Treat numbered SQL migrations as immutable. When adding a migration, add its SHA-256 digest to `checksums.json` in the same change. The migrator validates the complete manifest before applying SQL and records each digest in `schema_migrations`; a mismatch stops startup before any migration executes. Existing rows created before checksums were recorded are backfilled after the source manifest has passed validation.
