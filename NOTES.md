# Engineering notes

A record of mistakes made while building maskplan, how each was caught, and what changed. Kept because a wrong claim that was caught is more useful to a reviewer than a clean history, and because audits ask how results were checked.

## Errors made and corrected

| Date | Error | How it was caught | Correction |
| --- | --- | --- | --- |
| 2026-10-17 | Estimated the prefix-MAC saving at under 10%; the measurement hashed short messages without the 64-byte pads | Re-measured with the real message shape before writing results | 18% on Postgres, 23% on MySQL; `bench/README.md` corrected |
| 2026-10-17 | Wrote that MySQL agent roles must never hold `SHOW VIEW` to keep the pads hidden | Tested it: `EXPLAIN` and the optimizer trace stay denied even with `SHOW VIEW` | Rule narrowed to no privileges on the key table or base tables (`docs/token-spec.md`) |
| 2026-10-17 | Postgres seeding overflowed `int` at 10M rows (`g * 7919`); 100k-row smoke tests were too small to hit it | First 10M-row run failed | `generate_series` over `bigint` |
| 2026-10-17 | `-skip-seed` ran against tables a smaller test run had replaced | The benchmark's own token check stopped before timing anything | `-skip-seed` verifies row counts |
| 2026-10-17 | A wait loop matched its own command line with `pgrep -f` and stalled a run for about 20 minutes | Noticed during a status check | Run restarted directly; no data affected |
| 2026-10-17 | The first Postgres plan test passed even with `security_barrier` on a column-only view. With zeroed parallel costs the planner still runs workers, but cannot push the aggregate into them; the earlier claim that the option "disables parallel workers" was imprecise | Mutation testing: each new test was run against a deliberately broken generator or view | The test asserts a partial aggregate below the Gather; the spec and code comments describe the real mechanism |
| 2026-10-18 | The first report recognized a maskplan token by its shape (two `sha256(` calls, `'tok_'`, a plan reading the key table). `coalesce(email, <token>)` and `<token> \|\| email` have that shape and return raw emails; both were reported MASKED and the role passed. This is the failure the review called unacceptable | An adversarial view written while testing the clean role | MASKED now requires the column's whole plan (JSON) to equal the plan of the token maskplan generates for that base column, key-table InitPlans included |
| 2026-10-18 | Lineage parsed `EXPLAIN` text output. A `'\n'` literal splits an expression across output rows, so column references after it were missed and a raw view column could produce no finding at all | Debugging why the plan comparison failed for a real masked view (the trim set contains `\n`) | Lineage reads `EXPLAIN (FORMAT JSON)` |
| 2026-10-18 | Two view shapes produced no finding at all, which reads as safe: whole-row references (`row_to_json(c)`) and uncorrelated scalar subqueries (`$0`, no `SubPlan` in the text) | Reading the lineage code for every way it could return nothing; established from the code, not by running the old version | Both are UNKNOWN, as are top nodes without an output list (`UNION ALL`); each is a fixture in `mpt_sneaky` |
| 2026-10-18 | The first report missed four paths: `REPLICATION` (a base backup copies the cluster), managed-service admin roles, `pg_read_all_stats` (query texts with literal values), and hex key literals in view definitions | Writing the limitations section of `docs/report.md` | UNKNOWN, UNKNOWN, WARN and KEY findings, with fixtures |
| 2026-10-18 | `inet::text` renders as `10.0.0.1/32`; the IP detector rejected it and the phone detector accepted it | Scan integration test | IP detector accepts the prefix form |
| 2026-10-18 | `go mod tidy` raised the `go` directive from 1.24.7 to 1.25 through a test-only dependency (`rogpeppe/go-internal` 1.16) | Reading the `go.mod` diff | Pinned go-internal 1.13.1; directive unchanged |
| 2026-10-18 | During mutation testing two mutants looked like survivors; one did not compile and the other panicked, and the output filter hid both | Re-ran with build errors and panics visible | Both are killed; the third survivor, alias collisions, cannot occur because `EXPLAIN` already makes aliases unique, and the check stays as a backstop |

## Design choices that failed under measurement

These were reasonable on paper and replaced after the 10M-row benchmark. Details and numbers are in `bench/README.md`.

| Choice | What went wrong | Replacement |
| --- | --- | --- |
| `security_barrier` on every masked view | Blocks partial aggregation in parallel workers on Postgres: full scan 44 s instead of 17 s | Only on row-filtered views |
| Key table in a `CROSS JOIN` on both engines | Postgres: serial nested loop once the key table is analyzed. MySQL: no hash join between masked views | Postgres scalar subqueries; MySQL const join on `id = 1` |
| Scalar subqueries for the pads on MySQL | Views become unmergeable and are materialized in full: 10M-row join 159 s | Const join on `id = 1`: 35 s |
| `translate()` and `regexp_replace()` normalization on Postgres, a 26-call `REPLACE()` chain on MySQL | 2 to 3.6 µs per row per step | `lower(x COLLATE "C")`, double `translate()`, ASCII fast path on MySQL |

## How results are checked

- Tokens: 28 vectors generated from Go, recomputed independently in Python, and run through the generated SQL on Postgres 13 to 17 and MySQL 8.0 and 8.4 in CI.
- Safety and plan shape: every test in `internal/sqlexpr/plan_test.go` was confirmed to fail against a deliberately broken version of the code it guards (pads via `CROSS JOIN`, `security_barrier` on a column-only view, raw email exposed, row filter without `security_barrier`).
- Report: every privilege path in `docs/report.md` has a fixture role that must be flagged, on Postgres 13 to 17; a clean role must pass and must fail again after each of ten added paths; the tests were run against deliberately broken versions of the token check, the subquery, whole-row and output-list checks.
- Benchmarks: every run first checks that the masked views return the Go reference's tokens and that both joins return the expected row count.
