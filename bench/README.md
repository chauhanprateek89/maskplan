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

## Reading the verdicts

The design review set these gates:

- **Full scan:** pass within 3x the unmasked scan; kill signal above 5x, with the prefix MAC as the fallback.
- **Lookup:** pass under 100 ms.

The full-scan gate compares masked data with reading raw columns from memory, which costs a fraction of a microsecond per row. Any per-row hash exceeds 5x of that, including the engine's own `md5()`. So the benchmark also reports:

- **Masked / md5 floor:** the masked scan against a scan that only calls `md5()` on each column, the cheapest hash SQL offers. This measures how close the token is to the best possible.
- **Added per row per column:** the absolute cost of masking. Multiply by rows scanned to see what an agent's query pays.

The prefix-MAC fallback replaces two SHA-256 calls with one. Measured on 2M rows in one process, it saves 18% on Postgres and 23% on MySQL: not enough to change a verdict, and not worth giving up standard HMAC.

## Results

Run on 2026-10-17 in a 4-vCPU cloud sandbox (Intel Xeon @ 2.10GHz, 15 GB RAM), databases installed locally, data fully in memory. Median of 3 runs, 10,000,000 users and 1,000,000 orders. Postgres used its default 2 parallel workers; MySQL runs each query on one thread. Not yet run on MySQL 8.4 or on a managed service.

| Engine | Query | Unmasked | md5() floor | Masked | Masked / unmasked | Masked / md5 floor | Added per row per column |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Postgres 16.15 | Full scan, 2 tokenized columns | 0.68 s | 5.37 s | 16.86 s | 24.9x | 3.1x | 0.81 µs |
| Postgres 16.15 | Lookup, 1,000 rows by primary key | 8.7 ms | | 14.3 ms | 1.6x | | |
| Postgres 16.15 | Join 10M users to 1M orders on email token | 5.84 s | | 19.21 s | 3.3x | | |
| MySQL 8.0.46 | Full scan, 2 tokenized columns | 3.85 s | 14.14 s | 52.62 s | 13.7x | 3.7x | 2.44 µs |
| MySQL 8.0.46 | Lookup, 1,000 rows by primary key | 7.3 ms | | 12.9 ms | 1.8x | | |
| MySQL 8.0.46 | Join 10M users to 1M orders on email token | 18.77 s | | 35.40 s | 1.9x | | |

"Added per row per column" is wall-clock time; on Postgres it is shared across three processes, so CPU cost is about 2.4 µs, close to MySQL's.

### Verdict

- **Lookups pass** on both engines: 14 ms and 13 ms for 1,000 rows, against a 100 ms budget.
- **Full scans fail the review's gate** (13.7x and 24.9x against a 5x kill line), but the gate cannot be met by any per-row hash: `md5()` alone is 3.7x on MySQL and 7.9x on Postgres. Against the `md5()` floor, tokens cost 3.1x on Postgres and 3.7x on MySQL.
- **Joins on tokens work** at 1.9x to 3.3x the cost of joining raw normalized emails.

Recommendation: keep HMAC-SHA256, and replace the full-scan gate with "masked within 4x of the `md5()` floor, measured on the target service". Both engines pass that today. In absolute terms, an agent query that scans 10M rows and reads two tokenized columns pays about 16 s on Postgres and 49 s on MySQL on this hardware, so the docs should steer agents to filtered queries and aggregates, not full scans.

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
| Postgres `security_barrier` views cannot use parallel workers | No `security_barrier` on column-only views; kept for row filters | Full scan 47 s to 17 s, join 43 s to 19 s |

### Still to run

- MySQL 8.4 and Postgres 17 on the same hardware.
- One managed instance each: Aurora MySQL and RDS or Cloud SQL Postgres, with production-like CPU counts.
- Data larger than memory, where I/O narrows every ratio.
