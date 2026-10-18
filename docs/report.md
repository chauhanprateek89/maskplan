# maskplan scan and report

`scan` labels the personal data in a database. `report --role` answers, for one role: which of that data can it read raw, by which privilege path, and would anyone know? Both only read. PostgreSQL 13 and later for now; MySQL comes next.

```bash
export MASKPLAN_DSN=postgres://admin@db.internal:5432/app

maskplan scan --schema public,billing            # writes classification.yaml
# review classification.yaml, set reviewed: true on checked entries, commit it
maskplan report --role ai_agent --schema public,billing
maskplan report --role ai_agent --json > report.json
```

Exit status: `0` nothing raw is reachable, `1` the report found raw personal data, key material, or a path it cannot trace, `2` an error. That makes `report` usable as a CI check on a staging copy of production grants.

## scan

For every column of every table, partitioned table, materialized view and foreign table in scope (partitions are covered by their root), `scan` combines:

- **The column name**, matched against rules for email, phone, name, address, postal code, date of birth, national ID, IBAN, card number, IP address, customer IDs, secrets and free text. `firstName`, `first-name` and `FIRST_NAME` all match.
- **A sample of values** (100 rows per table by default, `--sample`), for text, network and JSON types. A detector must match at least 80% of non-empty sampled values: email shape, IBAN with a valid mod-97 check, card number passing Luhn, IPv4 or IPv6 address, phone shape (dates and decimals excluded). Number columns are sampled only when their name already suggests a card number, phone number or national ID, since older schemas store those as `bigint` or `numeric`; other number columns are not, because amounts and IDs look like phone numbers.
- **The type**: a date-of-birth name on a text column is not trusted; JSON and XML columns with no other match are labeled `free_text` at confidence 0.3, because documents can hold personal data under any key.

Each entry records its label, a confidence and the evidence. Values matching a detector win (0.95 when the name agrees, 0.9 otherwise); a name rule alone gives 0.6, or 0.4 when sampled values contradict it. Sampled values stay in memory for one table and are never written anywhere.

Rescanning keeps every entry marked `reviewed: true` as it is, including entries for columns that no longer exist, so a dropped and re-added column does not silently lose its review.

**How rows are chosen.** The first rows of a table are a poor sample: they are often seed or migrated data, or NULL in columns added later. So a table with more rows than the sample size, by the planner's estimate, is read with `TABLESAMPLE` and a fixed seed, so rows come from the whole table and a rescan of unchanged data reads the same rows. Up to about 10,000 pages (80 MB) `BERNOULLI` picks rows at a rate aimed at the sample size; larger tables use `SYSTEM`, which picks whole pages, from at least 50 of them. Either way the result is capped at twice the sample size, taking rows in an order scattered across the sample rather than physical order. Smaller tables are read whole. A table without statistics is read with `LIMIT`, the first rows only. Every sampled column's evidence says which method was used, for example `sampled 98 rows with TABLESAMPLE BERNOULLI (1%) of about 10000`, so a reviewer knows what its confidence rests on. Run `ANALYZE` before scanning a database whose statistics are missing.

Foreign tables and unpopulated materialized views are classified by name and type only. The scanning user must be able to `SELECT` a column for it to be sampled.

**Token columns.** A column named `X_tok` next to a column `X` in the same table is recorded as `derived_from: X`, with `X`'s label. Materialized token columns are how maskplan will make tokens indexable. The report does not count a derived column as masked: its values are tokens only if whatever writes them computes tokens, which the report cannot yet verify. Until `apply` creates the trigger and the report checks it, reading one is `UNKNOWN`.

## report

Run it as an inspecting user that can read the catalog and the views in scope: the database owner or an admin role, not the role being reported on. It runs in a read-only transaction with a statement timeout.

### Statuses

| Status | Meaning | Fails the report |
| --- | --- | --- |
| `KEY` | The role can read the token key material, so it can test guesses against every token. | yes |
| `RAW` | The role can read a labeled column's real values. | yes |
| `UNKNOWN` | A path exists that the report cannot trace. Treat it as raw. | yes |
| `UNLABELED` | The role can read a column the classification does not list. Scan again. | yes |
| `WARN` | Not an exposure today, but should be reviewed. | no |
| `MASKED` | The role reads this labeled column only as maskplan tokens. | no |

The rule behind the table: a path the report cannot trace is `UNKNOWN`, never `MASKED`. Reporting "masked" while raw data is reachable is the one failure that would make the tool worse than nothing, so every shortcut errs toward `UNKNOWN`.

### What it checks

**Roles.** Every role the target can act as: itself, every role reachable by membership with inheritance, and every role it can `SET ROLE` to (a `NOINHERIT` member still reaches its granted roles that way). Before PostgreSQL 16 membership always allows `SET ROLE`; from 16 each grant's `INHERIT` and `SET` options are honored, and a grant with neither gives nothing.

**Tables, partitions, materialized views, foreign tables.** For each column, the server decides whether any reachable role can read it (`has_column_privilege` and `has_schema_privilege`), so the answer covers table grants, column grants, `PUBLIC`, ownership, superuser and `pg_read_all_data`. The report then names the path: owner, column grant, table grant, `PUBLIC`, superuser or `pg_read_all_data`, with the membership chain.

**Views.** The report plans `SELECT column FROM view` (`EXPLAIN (VERBOSE, FORMAT JSON)`) and follows the output expression to base columns:

- A plain reference to a labeled column, through any number of views or joins: `RAW`.
- A maskplan token of one base column: `MASKED`, but only if the column's whole plan is identical to the plan of the token expression maskplan generates for that column, including the InitPlans that read the key table. Having the token's shape is not enough: `coalesce(email, <token>)` has it and returns raw emails.
- Any other expression over a labeled column, including hashes without the key, hard-coded keys and keys copied to another table: `UNKNOWN`.
- Anything the report cannot follow: subqueries, `security_barrier` views, CTEs, set operations, whole-row references such as `row_to_json(c)`, function scans: `UNKNOWN`.

**Other paths.**

| Path | Status |
| --- | --- |
| `SECURITY DEFINER` function the role can execute, whose owner can read labeled columns | `UNKNOWN` |
| The same, for a function that belongs to an extension (named in the finding). On managed services extensions are owned by the admin role, which reads everything, so `UNKNOWN` would fail every role | `WARN` |
| A view that belongs to an extension (`pg_stat_statements`, PostGIS's `geometry_columns`), once per view. They read catalogs or extension functions, not application data; tracing them failed every role in the managed-service simulation | `WARN` |
| A column, or a view column passing one through, recorded as `derived_from` another (a materialized token column) whose filling is not verified | `UNKNOWN` |
| User mapping on a foreign server for the role or `PUBLIC` | `UNKNOWN` |
| `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` | `UNKNOWN` |
| `REPLICATION` attribute (a base backup copies the whole cluster) | `UNKNOWN` |
| Managed-service admin roles: `rds_superuser`, `cloudsqlsuperuser`, `azure_pg_admin`, `alloydbsuperuser` | `UNKNOWN` |
| `CREATEROLE` before PostgreSQL 16 (can grant itself `pg_read_all_data`) | `UNKNOWN` |
| `CREATEROLE` from PostgreSQL 16 | `WARN` |
| Any privilege on the key table, even one column | `KEY` |
| Key pads written as hex literals in any view or function definition (readable by every role) | `KEY` |
| Default privileges granting `SELECT` on future tables to the role or `PUBLIC` | `WARN` |
| `BYPASSRLS` where row-level security is in use | `WARN` |
| `pg_read_all_stats` or `pg_monitor` (query texts of other sessions) | `WARN` |
| Key table without exactly one row; publications that replicate it; standby connection; large objects | `WARN` |

**Settings.** How the role logs in (password, IAM on RDS or Cloud SQL, `NOLOGIN`), whether `pgaudit.log` records its reads, its connection limit, and its `statement_timeout`, marked advisory because a session can change it.

### Known limitations

These all err toward `UNKNOWN` or are outside what a catalog report can see. None of them produces a false `MASKED`.

- **Masking written another way is not recognized.** Row-filtered masked views (which keep `security_barrier`), masked views over joins, and hand-written masking show as `UNKNOWN`. They will be recognized once `apply` generates them, by the same plan comparison.
- **Rows are not evaluated.** The report is per column; row-level security policies are not interpreted.
- **Extension functions and views are trusted to the extent of a WARN.** A `SECURITY DEFINER` function or a view that belongs to an extension is reported but does not fail the report. Anyone who can run `ALTER EXTENSION ... ADD` (the extension's owner) could hide a function or a view that way; the finding still names it. Tables that belong to an extension are checked like any other.
- **Views over the system catalogs** pass when they only expose what `PUBLIC` can read there anyway. A view that reads a catalog `PUBLIC` cannot (`pg_authid`, which holds password hashes) is `UNKNOWN`, and so is one that calls functions the report cannot follow; GitLab's monitoring views are an example.
- **Invoker functions are not followed.** A function that is not `SECURITY DEFINER` runs with the caller's privileges, so it can only read what the report already lists.
- **Only the hex spelling of a hard-coded key is detected**, not base64 or a key split across literals.
- **Large objects** are noticed, not classified.
- **Outside the database**: `pg_hba.conf`, backups, dumps, logs and replicas taken elsewhere are not visible to a catalog query.

### Managed services

**Untested on real RDS, Cloud SQL and Azure Flexible Server; simulated only.** The `managed-sim` CI job builds [`testdata/managed`](../testdata/managed): PostgreSQL 16 with `pgaudit`, `pg_stat_statements` and PostGIS installed by a superuser, plus a stand-in extension shaped like vendor extensions (a `SECURITY DEFINER` function owned by the administrator, executable by `PUBLIC`). `internal/report/managed_test.go` creates roles shaped like RDS's (`rds_superuser` with `pg_monitor`, `rds_iam`, a master user that owns the application), scans the whole database and reports on an agent that logs in through `rds_iam` and reads only a masked view. The agent must pass, with IAM login, `pgaudit.log` and its limits shown; the master user must fail, as a managed admin and owner.

The simulation found two problems before any real service did: every masked view came out UNKNOWN wherever `pg_stat_statements` is loaded (the query identifier in `EXPLAIN` output differed between the two plans being compared), and every role failed on the extensions' own views. Both are fixed and covered by fixtures that run on every PostgreSQL version in CI. What the simulation cannot reproduce is each provider's real catalog: its own roles, extension versions and grants. Until maskplan has run against the real services, treat results there as unverified.

### How it is tested

`internal/report/postgres_test.go` builds a database with one role per privilege path and checks that each is flagged, on PostgreSQL 13 to 17 in CI: column, table and `PUBLIC` grants; inherited, multi-level and `NOINHERIT` membership; ownership through membership; superuser; `pg_read_all_data`; raw, nested and joined views; expression, subquery, `security_barrier`, keyless-hash, copied-key and hard-coded-key views; views that wrap a real token around raw data, split their expression with a newline literal, use whole-row references, uncorrelated subqueries, `UNION ALL`, CTEs or aggregates (five of these defeated the first version of the report, see [NOTES.md](../NOTES.md)); `SECURITY DEFINER` functions, user-defined and from an extension (a clean role must still pass with one executable by `PUBLIC`); materialized token columns; default privileges; foreign-server user mappings; whole and column-level key-table grants; partitions; materialized views; unlabeled columns; `CREATEROLE`; `REPLICATION`; server-file roles; statistics roles.

A clean role that reads only a maskplan-generated masked view must pass, and is checked to really receive tokens and be denied the base table. Then each of ten extra paths is granted to it in turn, and the report must fail every time.
