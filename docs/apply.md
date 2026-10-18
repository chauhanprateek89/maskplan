# maskplan plan, apply and destroy

`apply` compiles one YAML policy into native database objects: for each agent identity, a role that can log in (or not), a schema of masked views it can read, and its settings. Enforcement then lives in the database: any client that connects as that role gets masked data, with no proxy in the path. PostgreSQL 13 and later, and MySQL 8.0 and 8.4 ([differences](#mysql)). Tokens are the same on both engines, so agents can join across them.

```bash
maskplan scan --dsn "$ADMIN_DSN"          # classification.yaml: review it and commit it
maskplan init                             # maskplan.yaml: a commented starter policy to review
maskplan plan                             # print the SQL apply would run; changes nothing
maskplan apply --yes                      # run it in one transaction, then report on every identity
maskplan report --dsn "$ADMIN_DSN" --role support_agent --policy maskplan.yaml
maskplan destroy --yes                    # drop everything apply created, the key included
```

`apply` without `--yes` prints the plan and changes nothing. After applying, it runs `report --policy` on every identity of the source and exits 1 if any report fails: the views are checked by the same code an auditor would run, not trusted because apply wrote them.

## The policy

`maskplan init` writes a starter from `classification.yaml`: one identity (`--identity`, default `ai_agent`) reading every classified table, and one rule per label found, with conservative suggestions. Emails, phones, IP addresses and usernames are tokenized. Names become fake names, birth dates their year, and postcodes their first three characters. Street addresses, government IDs, bank accounts, cards, secrets, gender and marital status are excluded. Each rule carries a comment with its column count and reason; review them all. It never overwrites an existing file.

```yaml
version: 1
key: env:MASKPLAN_KEY            # the HMAC key; never written in the file
sources:
  app:
    engine: postgres
    dsn: env:APP_ADMIN_DSN       # an admin connection; a literal DSN works too
    classification: classification.yaml   # relative to this file; the default
identities:
  support_agent:
    sources: [app]
    tables: [public.customers, public.tickets]   # or app:public.customers
    login: password              # iam (RDS rds_iam) | password | none
    password: env:SUPPORT_AGENT_PASSWORD
    audit: read                  # pgaudit.log = 'read' for this role; needs pgaudit
    limits:
      connections: 5             # enforced by the server
      statement_timeout: 30s     # advisory: a session can override it
    rows:
      public.tickets: b.tenant_id = 42   # SQL over the base table, aliased b
defaults:
  unlabeled: exclude             # columns the classification does not list: exclude | allow
  free_text: null                # columns labeled free text: null | exclude | allow
rules:
  - { label: user.contact.email, transform: token }
  - { label: user.contact.phone, transform: token }
  - { label: user.name, transform: fake_name }
  - { label: user.demographic.date_of_birth, transform: generalize_year }
  - { label: user.contact.address.postal_code, transform: prefix, params: { keep: 3 } }
overrides:
  - { column: app.public.customers.nickname, transform: "null" }
```

Unknown keys are errors, so a misspelled option fails instead of silently taking a default.

**How a column is decided**, in order: an override for that column; the rule for its label; `allow` for columns labeled `none`; `defaults.free_text`; `defaults.unlabeled` for columns the classification does not list. A personal-data label with no rule is excluded: the policy fails closed, so labeling a new column never exposes it. Columns recorded as `derived_from` another (materialized token columns) are excluded for now.

**Transforms.**

| Transform | Result |
| --- | --- |
| `token` | `tok_` and 16 hex characters of HMAC-SHA256 of the normalized value ([spec](token-spec.md)); the same value gives the same token in every view and engine, so agents can join and count |
| `fake_name` | a name from a fixed 4,096-name dictionary, picked by the value's keyed index; consistent per value, not unique, never a join key |
| `fake_email` | that name as `first.last@example.invalid` (the `.invalid` domain cannot receive mail) |
| `generalize_year`, `generalize_month` | a date or timestamp truncated to January 1 or the first of the month |
| `prefix` | the first `keep` characters, 1 to 8: a postcode's routing key, an IBAN's country and bank |
| `null` | the column, always `NULL` (write it `"null"` or `null`) |
| `exclude` | no column |
| `allow` | the raw value; `plan` warns for every labeled column allowed |

Tokens of low-entropy labels (dates of birth, postcodes, gender) get a warning in the plan: with the key, they can be reversed by trying every possible value. Generalize or prefix them instead.

## What apply creates

On each Postgres source, in one transaction:

- `maskplan_internal` (`--internal-schema`), usable by no role but the one running apply, with
  - `key_material`: the key as HMAC pads, one row. Written with bind parameters, so the key never appears in SQL text, server logs or the printed plan;
  - `names`: the fake-name dictionary;
  - `objects`: what apply created. apply changes and drops only what is recorded there, and refuses an identity whose role or schema already exists and is not recorded.
- Per identity:
  - a role, `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, with `LOGIN` unless `login: none`. A password is sent as a SCRAM verifier, never as the password, and is not printed; `login: iam` grants `rds_iam`;
  - a schema of the same name, set as its `search_path`, with one view per table. The views are owned by the user running apply and read base tables with its rights, so the role needs, and gets, no privilege on any base table or on `maskplan_internal`;
  - `CONNECTION LIMIT`, `statement_timeout`, and `pgaudit.log = 'read'` as asked.
- Views are named after their tables, so an identity cannot have two tables of the same name from different schemas; apply refuses rather than let one view replace the other.
- A view with a `rows` filter is a `security_barrier` view. Without the barrier, the planner could run the role's own `WHERE` clause first, and a function in it would see every row's values. Views without a filter are plain, so the planner can still flatten them and run aggregates in parallel workers ([benchmark](../bench/README.md)).
- Identities removed from the policy are dropped: their views, their schema, and their role (after `DROP OWNED BY`, which removes grants someone added by hand).

`destroy` drops every recorded object and then `maskplan_internal` with the key. Tokens made with that key cannot be recomputed afterwards unless you still have the key.

apply refuses to run while a publication replicates all tables (`FOR ALL TABLES`), which would include the key table.

## MySQL

The same policy works with `engine: mysql`, with these differences:

- A **database** plays the part of a schema: each identity gets an account `'name'@'%'` and a database of the same name holding `SQL SECURITY DEFINER` views. The views are defined by the account running apply, which needs `SELECT` on the base tables and the right to create users and grant.
- **No transaction.** MySQL commits DDL as it goes, so an apply that fails part way leaves part of the plan done. Every statement is idempotent: run apply again to finish it.
- **Passwords** are sent as `ALTER USER ... IDENTIFIED BY '...'`, which MySQL rewrites without the password in its general, slow and binary logs; the plan shows `'…'`. Passwords containing `'` or `\` are refused, since quoting them depends on the server's SQL mode. `login: iam` uses `AWSAuthenticationPlugin` (RDS and Aurora); `login: none` locks the account.
- **Refused:** `rows` filters, because MySQL has no security barrier, so a session's own conditions can be evaluated on rows a view's filter excludes; and `audit: read`, because audit plugins filter by account in their own configuration. `statement_timeout` is ignored with a warning: MySQL has no per-account setting.
- **Grants survive `DROP VIEW`** on MySQL, ready to apply to a later view with the same name, so apply revokes them before dropping a view.
- The key's `INSERT` is in the **binary log** when binary logging is on; `report` warns about it.

## Checking it: report --policy

Without `--policy`, `report` recognizes every transform apply generates by plan comparison (see [report.md](report.md)), so it says which columns are masked. A rows filter does not change what a column's values are, so column findings cannot say whether the role sees the right rows. With `--policy`, report compiles each of the role's views from the policy and compares:

- the view's columns, by name and order;
- that a filtered view is a `security_barrier` view;
- the plan of `SELECT * FROM view` with the plan of the compiled view, so a transform, a join or the rows filter that differs fails. The fixtures drop the filter, filter on another column, append `OR true`, drop the barrier, and add a raw column; each must fail the report, and `apply` must then restore the view.

A view that differs is `UNKNOWN`; one that is missing is `WARN`. Without `--policy`, each filtered view gets a `WARN` naming its filter as not checked.

On MySQL, where views have no rows filter, `--policy` compares the column list, each column's transform and base column (as the report recognizes them), and requires no `WHERE`, `GROUP BY`, `HAVING`, `LIMIT` or `UNION`. The fixtures add a raw column, replace a fake email with another column, and add a `WHERE` clause; each must fail.

## How it is tested

Fixtures in `internal/apply` and `cmd/maskplan` apply policies with every transform on both engines and require the report to pass (see [report.md](report.md#how-it-is-tested)). Beyond fixtures, the `maskplan init` starter was applied unchanged to three realistic schemas, and apply's own report had to pass:

| Schema | Engine | Columns masked | What it found first |
| --- | --- | --- | --- |
| Synthetic Irish bank (`testdata/fintech`) | PostgreSQL 16 | 19 | Columns of a partitioned table were UNKNOWN |
| Sakila | MySQL 8.0 | 11 | Masking over `NOT NULL` columns was not recognized |
| AdventureWorks (5 schemas) | PostgreSQL 16 | 10 | Nothing |

Both failures were in the safe direction (UNKNOWN, never MASKED) and are fixed; see [NOTES.md](../NOTES.md).

## Not yet

- Rows filters and `audit: read` on MySQL.
- `derived_from` token columns (materialized tokens kept by a trigger).
- Key rotation: changing `key` re-keys every token; there is no overlap period.
- Real managed services: as for report, RDS, Cloud SQL and Azure are simulated, not tested.
