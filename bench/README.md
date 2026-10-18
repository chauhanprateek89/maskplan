# Benchmark

Measures what tokenization costs on Postgres and MySQL, using the same SQL the compiler will generate. This is the design's week-1 benchmark: it decides whether the HMAC construction is fast enough before any compiler code is written.

## What it does

1. Seeds `maskplan_bench.users` (default 10,000,000 rows) and `maskplan_bench.orders` (default 1,000,000 rows) on the server. Users have mixed-case emails, a leading space on every tenth row, formatted phone numbers and some non-ASCII names. Orders reference users by lowercase email, so the join only matches after normalization.
2. Writes a fresh random key's pads to `maskplan_internal.key_material` and creates two masked views, `v_users` (email and phone tokenized) and `v_orders` (email tokenized).
3. Checks that the views return exactly the tokens the Go reference computes, and that both joins return one row per order.
4. Times each query `-runs` times (default 3) and reports the median:

| Query | Unmasked side | Masked side |
| --- | --- | --- |
| Full scan | `max(email), max(phone)` over `users` | the same over `v_users` |
| md5 floor | `max(md5(email)), max(md5(phone))` over `users` | |
| Lookup | 1,000 random primary keys from `users` | the same from `v_users` |
| Find by token | one user by raw email, using an index on `email` | one user by email token, which has no index |
| Join | `users` to `orders` on normalized email | `v_users` to `v_orders` on the email token |

The unmasked join compares normalized emails, so its ratio isolates the cost of hashing rather than normalization.

## Running it

```bash
docker compose -f bench/docker-compose.yml up -d --wait
go run ./bench -engine postgres -dsn postgres://maskplan:maskplan@localhost:55432/maskplan -json pg.json
go run ./bench -engine mysql -dsn 'root:maskplan@tcp(127.0.0.1:53306)/maskplan' -json mysql.json
docker compose -f bench/docker-compose.yml down -v
```

For a managed service (Aurora MySQL, RDS, Cloud SQL), point `-dsn` at an admin user on a non-production instance. The tool creates and drops the `maskplan_bench` and `maskplan_internal` schemas; `-cleanup` drops them and exits. `-skip-seed` reuses tables from a previous run with the same `-rows` and `-orders`.

Other flags: `-rows`, `-orders`, `-runs`, `-lookup`, `-join-mem` (session `work_mem` or `join_buffer_size`, applied equally to both sides of every comparison).

## Gates

Agreed in the week-1 review. A masked full scan passes when both hold on the target service:

- **CPU cost:** at most 5 µs per row per tokenized column, measured with one process (Postgres parallel workers disabled; MySQL is single-threaded anyway). This is the user-facing number: multiply it by rows scanned and tokenized columns read to see what an agent's query pays.
- **Environment check:** the masked scan within 4x of a scan that only calls `md5()` on each column, the cheapest per-row hash SQL offers. A higher ratio points at the setup, not the token design.

Point lookups by primary key must finish under 100 ms.

The design-v3 gate (masked scan within 3x of the unmasked scan, kill above 5x) is still printed for reference. No per-row hash can meet it: reading in-memory columns costs a fraction of a microsecond per row, so `md5()` alone is 4x to 9x.

The prefix-MAC fallback replaces two SHA-256 calls with one. Measured on 2M rows in one process, it saves 18% on Postgres and 23% on MySQL: not enough to change a verdict, and not worth giving up standard HMAC.

## Results

Run on 2026-10-17 in a 4-vCPU cloud sandbox (Intel Xeon @ 2.10GHz, 15 GB RAM), databases installed locally, data fully in memory. Median of 3 runs, 10,000,000 users and 1,000,000 orders. Postgres used its default 2 parallel workers except for the one-process CPU measurement; MySQL runs each query on one thread. Raw results: `bench/results/`.

| Engine | Query | Unmasked | md5() only | Masked | Masked / unmasked | Masked / md5 | CPU per row per column |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Postgres 16.15 | Full scan, 2 tokenized columns | 0.59 s | 5.43 s | 16.63 s | 28.3x | 3.1x | 2.23 µs |
| Postgres 16.15 | Lookup, 1,000 rows by primary key | 5.5 ms | | 10.7 ms | 1.9x | | |
| Postgres 16.15 | Find one user by email token | 0.2 ms (indexed) | | 6.68 s | | | |
| Postgres 16.15 | Join 10M users to 1M orders on email token | 4.85 s | | 17.25 s | 3.6x | | |
| MySQL 8.0.46 | Full scan, 2 tokenized columns | 4.17 s | 15.90 s | 52.76 s | 12.7x | 3.3x | 2.43 µs |
| MySQL 8.0.46 | Lookup, 1,000 rows by primary key | 7.2 ms | | 12.1 ms | 1.7x | | |
| MySQL 8.0.46 | Find one user by email token | 0.2 ms (indexed) | | 25.32 s | | | |
| MySQL 8.0.46 | Join 10M users to 1M orders on email token | 18.38 s | | 34.29 s | 1.9x | | |

### Verdict

- **Full scans pass** the agreed gates on both engines: 2.23 and 2.43 µs CPU per row per column against a 5 µs budget, and 3.1x and 3.3x the `md5()` floor against 4x.
- **Lookups by primary key pass:** 11 ms and 12 ms for 1,000 rows against 100 ms.
- **Token joins work** at 1.9x to 3.6x the cost of joining raw normalized emails.

### Known costs

These are by design today; agents and their operators should know them before relying on masked data.

| Query shape | Cost on 10M rows | Why | Fix |
| --- | --- | --- | --- |
| Find one row by token (`WHERE email = 'tok_...'`) | 6.7 s Postgres (3 processes), 25 s MySQL; about 0.2 ms on an indexed raw column | Tokens are computed per row; there is nothing to index | Trigger-maintained, indexed token columns (design note in `docs/token-spec.md`) |
| Full scan reading tokenized columns | About 2.3 µs CPU per row per tokenized column: 16.6 s Postgres, 53 s MySQL for two columns | Two SHA-256 calls plus normalization per value | Steer agents to filters and aggregates; materialized token columns remove it |
| Join on a token | 17 s Postgres, 34 s MySQL for 10M to 1M | Both sides hash every row | Materialized token columns make it an ordinary indexed join |
| Lookup by primary key | 11 to 12 ms for 1,000 rows | Only the selected rows are hashed | None needed |

### What the benchmark changed

The first runs were much slower. Each fix below is now in `internal/sqlexpr`:

| Problem found | Fix | Effect |
| --- | --- | --- |
| Postgres `translate()` for ASCII lowercasing cost 3.6 µs per row | `lower(x COLLATE "C")`, which maps ASCII only | Email normalization about 13x cheaper |
| Postgres `regexp_replace()` for phone digits cost 2 µs per row | Double `translate()` that deletes every non-digit | About 2x cheaper |
| MySQL 26-step `REPLACE()` chain cost 3 µs per row | `LOWER()` when the value is pure ASCII, the chain only otherwise | About 4x cheaper on typical data |
| MySQL views with the key table in a `CROSS JOIN` could not hash-join on a token | `JOIN key_material ON id = 1`, a const table | 100k-row join no longer hangs |
| MySQL views with pads in scalar subqueries were materialized in full | Same const-table join | 10M-row join 159 s to 35 s |
| Postgres `CROSS JOIN` lost parallel workers once the key table was analyzed | Pads read through scalar subqueries | Plan independent of statistics |
| Postgres `security_barrier` views cannot push aggregates into parallel workers | No `security_barrier` on column-only views; kept for row filters | Full scan 47 s to 17 s, join 43 s to 19 s |

### Still to run

1. Managed services: Aurora MySQL and RDS Postgres, with production-like CPU counts, and data larger than memory, where I/O narrows every ratio.
2. Row-filtered views, which every multi-tenant policy needs. They keep `security_barrier`; if it costs Postgres 2.6x there too, the likely answer is an owner-rights row-level security policy on the base table instead of a filter in the view, which changes what `apply` generates.
3. MySQL 8.4 and Postgres 17 on the same hardware as above.
