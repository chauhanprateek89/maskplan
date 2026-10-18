# maskplan scan and report

`scan` labels the personal data in a database. `report --role` answers, for one role: which of that data can it read raw, by which privilege path, and would anyone know? Both only read. PostgreSQL 13 and later, and MySQL 8.0 and 8.4 (see [MySQL](#mysql)).

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

On MySQL, which has no `TABLESAMPLE`, tables up to 100 times the sample size are sampled with `ORDER BY RAND` and a fixed seed (MySQL keeps only the top rows while it scans); larger tables with a single integer primary key are read in ten evenly spaced key ranges, and other large tables with one pass of `WHERE RAND() < p`. If that pass exceeds the 60-second statement limit, the first rows are read and the evidence says so. Booleans are `tinyint(1)` and `bit(1)`.

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
- A maskplan transform of one base column (`token`, `fake_name`, `fake_email`, `generalize_year`, `generalize_month`, `prefix` of up to 8 characters; see [apply.md](apply.md)): `MASKED`, naming the transform, but only if the column's whole plan is identical to the plan of the expression maskplan generates for that column, including the InitPlans that read the key table and the dictionary join of fake values. Having a transform's shape is not enough: `coalesce(email, <token>)` has it and returns raw emails.
- Before plans are compared, InitPlans that nothing references are dropped and the rest renumbered, and relation aliases are renamed by table and order. Reading one column of a view leaves behind the InitPlans of joins the planner removed, and numbers everything by the view's full column list; neither changes the column's values. Each rename maps distinct names to distinct names and leaves literals alone, so plans that differ still differ.
- A view read through a Subquery Scan (`security_barrier` views, and subqueries kept with `OFFSET 0`) is traced through it: the planner replaces every subquery output the query does not use with a `NULL`, so the one output that is not `NULL` is the column, whatever order the view lists its subquery's columns in. The reference for such a column is the same subquery with the view's own `WHERE` clause.
- Any other expression over a labeled column, including hashes without the key, hard-coded keys and keys copied to another table: `UNKNOWN`.
- Anything the report cannot follow: correlated subqueries, CTEs, set operations, whole-row references such as `row_to_json(c)`, function scans, a Subquery Scan with two non-`NULL` outputs: `UNKNOWN`.
- A view's own conditions (`WHERE`, join conditions) run on base rows whatever the role selects, so a condition that reads a labeled column can pass its raw values on: `WHERE email::int > 0` fails with each email in the error message, and a function in the condition can raise it as a notice. Such a view is `UNKNOWN`, unless `--policy` says it is the policy's view.

**Policy (`--policy maskplan.yaml`).** The role's views are compared with the ones the policy compiles to: columns, `security_barrier` on filtered views, and the plan of `SELECT *`, which covers transforms and rows filters. A view that differs is `UNKNOWN`, a missing one `WARN`. Without `--policy`, a filtered view gets a `WARN` showing its filter as not checked. Details in [apply.md](apply.md#checking-it-report---policy).

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

- **Masking written another way is not recognized.** Masked views over joins and hand-written masking show as `UNKNOWN`: only the expressions `apply` generates are compared.
- **Rows are checked only against a policy.** The report is per column; without `--policy` a rows filter is shown, not verified, and row-level security policies are not interpreted.
- **View conditions are checked only where the plan shows them** on columns it can trace. A condition on a CTE or subquery output is not traced back to base columns. On MySQL only `WHERE` clauses are checked, not join conditions.
- **Extension functions and views are trusted to the extent of a WARN.** A `SECURITY DEFINER` function or a view that belongs to an extension is reported but does not fail the report. Anyone who can run `ALTER EXTENSION ... ADD` (the extension's owner) could hide a function or a view that way; the finding still names it. Tables that belong to an extension are checked like any other.
- **Views over the system catalogs** pass when they only expose what `PUBLIC` can read there anyway. A view that reads a catalog `PUBLIC` cannot (`pg_authid`, which holds password hashes) is `UNKNOWN`, and so is one that calls functions the report cannot follow; GitLab's monitoring views are an example.
- **Invoker functions are not followed.** A function that is not `SECURITY DEFINER` runs with the caller's privileges, so it can only read what the report already lists.
- **Only the hex spelling of a hard-coded key is detected**, not base64 or a key split across literals.
- **Large objects** are noticed, not classified.
- **Outside the database**: `pg_hba.conf`, backups, dumps, logs and replicas taken elsewhere are not visible to a catalog query.

### MySQL

`--role` names an account, `user@host`, or `user` when only one account has that name. The report runs as an inspecting account that can read the `mysql` schema and `EXPLAIN` the views in scope, in a read-only transaction with a statement limit.

MySQL has no function that says whether an account can read a column, so the report evaluates the grant tables itself (`mysql.user`, `db`, `tables_priv`, `columns_priv`, `procs_priv`, `global_grants`, `proxies_priv`). Where it does not model something, it over-reports.

**Accounts and roles.** The account itself, every role granted to it directly or through other roles (all can be activated with `SET ROLE`; the finding says which are active at login, by default role or `activate_all_roles_on_login`), and the server's `mandatory_roles`.

**Tables.** A column is readable through global `SELECT`, `SELECT` on a database (patterns with `_` and `%` included), on the table, or on the column. Labeled columns are `RAW`; unlisted ones `UNLABELED`.

**Views.** The optimizer's rewritten statement (`EXPLAIN` then `SHOW WARNINGS`) shows a merged view column in terms of base columns: a plain reference is `RAW`. A column is `MASKED` only if its stored definition is identical to the optimizer's printing of the expression maskplan generates for that base column (token, fake name or email, generalized date, prefix of up to 8), with the same aliases, reading the real key table. For fake values the dictionary join's index expression in the stored definition must also equal the generated one. If the optimizer read any data table as a constant (one row, or a primary-key filter), values from the data replace column references in the rewrite, so the column is `UNKNOWN`; so are subqueries, materialized views and anything else the report cannot follow. A view whose `WHERE` clause reads a labeled column is `UNKNOWN`: it runs on every row, and an error in it (`JSON_EXTRACT` on a value that is not JSON) carries the value. With `--policy`, views are compared with the policy column by column ([apply.md](apply.md#checking-it-report---policy)).

| Path | Status |
| --- | --- |
| `SQL SECURITY DEFINER` routine the account can execute | `UNKNOWN` |
| `PROXY` for another account | `UNKNOWN` |
| `FILE`, `SUPER`, `CREATE USER`, global `GRANT OPTION`, `REPLICATION SLAVE`, `SET_USER_ID`, `SET_ANY_DEFINER`, `ROLE_ADMIN`, `BACKUP_ADMIN`, `CLONE_ADMIN` | `UNKNOWN` |
| `SELECT` on `mysql.user` (account password hashes) | `UNKNOWN` |
| Any privilege on the key table, or the key in a view or routine definition | `KEY` |
| `PROCESS` (other sessions' statements), `AUDIT_ADMIN` | `WARN` |
| Partial revokes (not evaluated: global grants are taken to apply everywhere); anonymous accounts; binary logging on (the key's `INSERT` is in the binlog) | `WARN` |

**Settings.** The authentication plugin (`AWSAuthenticationPlugin` is reported as IAM), account locked or password expired, `max_user_connections`, an active audit plugin (`audit_log`, `server_audit`), and the server's `max_execution_time`.

**Limits specific to MySQL.** Host matching at login is not evaluated: the report covers the one account named, and warns when anonymous accounts exist. Definer routines are not traced into: every one the account can execute is `UNKNOWN`. `SQL SECURITY INVOKER` views are traced like definer views, which over-reports. A masked view over a table with one row cannot be verified (`UNKNOWN`) until it has more.

### Managed services

**Untested on real RDS, Cloud SQL and Azure Flexible Server; simulated only.** The `managed-sim` CI job builds [`testdata/managed`](../testdata/managed): PostgreSQL 16 with `pgaudit`, `pg_stat_statements` and PostGIS installed by a superuser, plus a stand-in extension shaped like vendor extensions (a `SECURITY DEFINER` function owned by the administrator, executable by `PUBLIC`). `internal/report/managed_test.go` creates roles shaped like RDS's (`rds_superuser` with `pg_monitor`, `rds_iam`, a master user that owns the application), scans the whole database and reports on an agent that logs in through `rds_iam` and reads only a masked view. The agent must pass, with IAM login, `pgaudit.log` and its limits shown; the master user must fail, as a managed admin and owner.

The simulation found two problems before any real service did: every masked view came out UNKNOWN wherever `pg_stat_statements` is loaded (the query identifier in `EXPLAIN` output differed between the two plans being compared), and every role failed on the extensions' own views. Both are fixed and covered by fixtures that run on every PostgreSQL version in CI. What the simulation cannot reproduce is each provider's real catalog: its own roles, extension versions and grants. Until maskplan has run against the real services, treat results there as unverified.

### How it is tested

`internal/report/postgres_test.go` and `mysql_test.go` build a database with one role or account per privilege path and checks that each is flagged, on PostgreSQL 13 to 17 in CI: column, table and `PUBLIC` grants; inherited, multi-level and `NOINHERIT` membership; ownership through membership; superuser; `pg_read_all_data`; raw, nested and joined views; expression, subquery, `security_barrier`, keyless-hash, copied-key and hard-coded-key views; a fake name that falls back to the raw value, a fake name keyed by another column, a 9-character prefix, a subquery whose columns the view lists in another order, a condition whose cast error carries the email; views that wrap a real token around raw data, split their expression with a newline literal, use whole-row references, uncorrelated subqueries, `UNION ALL`, CTEs or aggregates (five of these defeated the first version of the report, see [NOTES.md](../NOTES.md)); `SECURITY DEFINER` functions, user-defined and from an extension (a clean role must still pass with one executable by `PUBLIC`); materialized token columns; default privileges; foreign-server user mappings; whole and column-level key-table grants; partitions; materialized views; unlabeled columns; `CREATEROLE`; `REPLICATION`; server-file roles; statistics roles.

A clean role that reads only a maskplan-generated masked view (tokens, a fake name, a prefix) must pass, and is checked to really receive tokens and be denied the base table. Then each of ten extra paths is granted to it in turn, and the report must fail every time.

`internal/apply/postgres_test.go` applies a policy with every transform, a password login and a row-filtered identity, and requires the report to pass for both identities with and without `--policy`; the agent logs in and gets the expected token, a dictionary name, the year, the prefix and `NULL`, and is denied the base table, the key and the dictionary. Then the filtered view is rewritten five ways (filter dropped, filter on another column, `OR true`, barrier dropped, a raw column added): `--policy` must fail each, and a second apply must restore it.
