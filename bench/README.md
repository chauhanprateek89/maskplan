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

The prefix-MAC fallback replaces two SHA-256 calls with one. Profiling shows the second call costs under 10% of a token, so the fallback cannot change a verdict.

## Results

<!-- results -->
