# SQLx Query Cache (Offline Mode)

This folder contains the **SQLx metadata cache** for offline mode.

## Purpose

SQLx's `query!` and `query_as!` macros perform **compile-time SQL validation**. This requires database connectivity during compilation, which is problematic for:
- CI/CD pipelines
- Clean builds without database
- Reproducible builds

The `.sqlx/` cache solves this by storing query metadata, allowing compilation without a live database.

## Contents

```
.sqlx/
└── query-<hash>.json  # Cached metadata for each query
```

Each file contains:
- Query SQL
- Parameter types
- Result column types
- Database schema at query time

## Usage

### Compile with Cache (Offline Mode)

```bash
# Normal build uses cache automatically
cargo build

# SQLx uses SQLX_OFFLINE=true implicitly when cache exists
```

### Regenerate Cache

When you modify SQL queries or database schema:

```bash
# Using Make (recommended)
make sqlx-prepare

# Or manually
DATABASE_URL="sqlite:///tmp/wafrust.db" cargo sqlx prepare
```

This will:
1. Create a temporary database
2. Run migrations
3. Extract metadata for all queries
4. Update `.sqlx/*.json` files

### When to Regenerate

Regenerate the cache when:
- ✅ You add/modify SQL queries
- ✅ You change database schema (migrations)
- ✅ You change query result types
- ❌ You only change Rust code (no need)

## CI/CD

The cache is **committed to git** to enable:
- Builds without database connectivity
- Faster CI/CD (no database setup needed)
- Reproducible builds

## Troubleshooting

### "Error: DATABASE_URL not set"

If you see this error during `cargo build`:
1. Cache is missing or outdated
2. Run `make sqlx-prepare` to regenerate
3. Commit updated cache files

### "Query type mismatch"

Your code and cache are out of sync:
1. Run `make sqlx-prepare`
2. Rebuild: `cargo clean && cargo build`

### Cache Files Are Large

This is normal. Query metadata includes full schema information.
All files are JSON and compress well in git.

## How It Works

**With Cache (Offline Mode)**:
```
cargo build
  → sqlx macro detects .sqlx/ exists
  → reads cached metadata
  → validates query at compile-time
  → no database needed ✅
```

**Without Cache (Online Mode)**:
```
cargo build
  → sqlx macro connects to DATABASE_URL
  → queries live database for metadata
  → validates query at compile-time
  → requires database running ❌
```

## Learn More

- [SQLx Offline Mode Docs](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode)
- [SQLx GitHub](https://github.com/launchbadge/sqlx)
