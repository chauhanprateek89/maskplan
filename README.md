# maskplan

Terraform-style PII policies for Postgres and MySQL, so AI agents query masked data instead of customer records.

> **Pseudonymized is not anonymous.** maskplan replaces values with keyed tokens. Anyone holding the key can test a guessed value, and under GDPR tokenized data is still personal data. Treat it as a way to limit exposure, not as anonymization.

**Try it in ten minutes** with only Docker: [demo/README.md](demo/README.md) finds five access mistakes on a synthetic bank, then builds a clean agent login.

## Status

Pre-alpha. What works today, on PostgreSQL 13 to 17 and MySQL 8.0 and 8.4:

- `maskplan scan` labels personal data from column names, types and a sample of values, and writes `classification.yaml` for review;
- `maskplan report --role` lists every labeled column a role can read raw, by which privilege path, and whether its reads are audited. Anything it cannot trace is reported as UNKNOWN, never as masked. See [docs/report.md](docs/report.md).
- `maskplan plan` and `apply` compile a YAML policy into a login role per agent identity with a schema of masked views (tokens, fake names, generalized dates, prefixes, and row filters on Postgres), audit settings and limits, and then run `report` on every identity to check the result. `destroy` removes it all. See [docs/apply.md](docs/apply.md).

On a synthetic Irish bank held out from tuning, `scan` finds every email, IBAN, card number and phone column (recall 1.00 at 100 to 10,000 sampled rows; this is a CI gate), with 0.87 precision and recall for personal data overall. On AdventureWorks, which it was tuned on, 0.86 precision and 0.96 recall. On GitLab's 11,000-column schema with no data, 0.92 precision outside free text and recall of about 0.74. Method, misses and gaps: [docs/accuracy.md](docs/accuracy.md). Managed services (RDS, Cloud SQL, Azure) are simulated in CI, not yet tested for real.

`scan` and `report` only read. Also here:

- the [token specification](docs/token-spec.md), with a Go reference implementation and generated Postgres and MySQL SQL that produce identical tokens;
- shared test vectors that every implementation must reproduce, checked on Postgres 13 to 17 and MySQL 8.0 and 8.4 in CI;
- a [benchmark](bench/README.md) of what masking costs on a 10-million-row table.

Next: a run on real managed services.

```bash
go install github.com/chauhanprateek89/maskplan/cmd/maskplan@latest
export MASKPLAN_DSN=postgres://admin@db.internal:5432/app
maskplan scan                       # writes classification.yaml; review and commit it
maskplan report --role ai_agent     # exit 1 if raw personal data is reachable
maskplan init                       # a starter maskplan.yaml from the classification
maskplan plan                       # the SQL apply would run
maskplan apply --yes                # masked views and roles, then a report on each
```

```
role: ai_agent    source: postgres 16.15, database app

RAW       public.customers.email  user.contact.email  SELECT on column granted to analysts (by SET ROLE: ai_agent > analysts)

login: password
audit: none: reads by this role are not logged
connection limit: none
statement timeout: none

1 raw. FAIL: raw personal data or key material is, or may be, reachable.
```

## The idea

AI agents increasingly get a database connection. Whatever they read lands in prompts, logs and third-party APIs. maskplan aims to:

1. **Report** what a database role can read raw, by every privilege path, and whether its reads are audited. Read-only and safe to run on a replica, even if you never adopt the rest.
2. **Compile** one YAML policy into native objects: a schema of masked views per agent identity, a role that can read only those views, audit settings, connection limits and IAM logins.
3. **Tokenize consistently**, so the same customer has the same token in Postgres and MySQL and agents can still join, group and count.

Enforcement lives in the database, so any MCP server, gateway, notebook or BI tool connecting with the agent's role gets masked data with no proxy in the path.

## How tokens work

```
token = "tok_" + hex(HMAC-SHA256(key, label + ":" + normalize(value)))[0:16]
```

- Labels such as `user.contact.email` namespace tokens; normalizers (`trim`, `email`, `phone`) are byte-exact and identical in every engine.
- SQL computes the HMAC from precomputed pads with built-in SHA-256, so it needs no extension and no stored function.
- Key material lives in a table agents cannot read and is never written into view definitions, which Postgres exposes to every role.

Details, edge cases and the exact SQL are in [docs/token-spec.md](docs/token-spec.md).

## Why not PostgreSQL Anonymizer?

[PostgreSQL Anonymizer](https://postgresql-anonymizer.readthedocs.io/) is a good tool for Postgres. maskplan targets a different gap:

- It needs an extension that some major managed services do not offer; maskplan uses only built-in SQL.
- It covers Postgres only; maskplan covers Postgres and MySQL with the same policy.
- It has no exposure report for roles you already have.
- Its pseudonyms are not designed to match tokens produced in another engine.

## Development

```bash
go test ./...                       # unit tests and vector freshness
python3 scripts/check_vectors.py    # independent check of the vectors
go run ./cmd/genvectors             # regenerate testdata/vectors.json after changing cases

# Vectors, scan, report and apply fixtures against live databases. The
# fixtures create cluster-wide roles named mpt_*, mpa_* and mpc_*; use a throwaway server
# and a superuser DSN. -p 1 keeps packages from seeing each other's grants.
MASKPLAN_TEST_POSTGRES_DSN=postgres://user:pass@localhost:5432/db \
MASKPLAN_TEST_MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/db' \
go test ./... -p 1 -v
```

| Path | Contents |
| --- | --- |
| `cmd/maskplan` | The CLI |
| `internal/classify`, `internal/classification` | Column classifier and `classification.yaml` |
| `internal/scan` | Postgres and MySQL scanners |
| `internal/report` | Exposure report and its adversarial fixtures |
| `internal/policy`, `internal/compile`, `internal/apply` | `maskplan.yaml`, the compiler from policy to SQL, and running it |
| `internal/token` | Go reference implementation of the token spec |
| `internal/sqlexpr` | Postgres and MySQL expression generators, and the live-database vector tests |
| `internal/vectors`, `testdata/vectors.json` | Shared test vectors and their generator |
| `bench/` | Benchmark harness and Docker Compose setup |
| `docs/token-spec.md` | Token specification, version 1 |
| `docs/report.md` | What scan and report check, statuses and limitations |
| `docs/apply.md` | The policy file, transforms, and what apply creates |
| `docs/accuracy.md` | Classifier precision and recall, and how they are measured |
| `internal/fintech`, `testdata/fintech` | Synthetic Irish bank: generator, schema and ground truth |
| `testdata/adventureworks` | Ground truth for AdventureWorks |
| `testdata/gitlab` | Hand review of a scan of GitLab's schema |
| `testdata/sakila` | Ground truth for Sakila (MySQL) |
| `testdata/managed` | Simulated managed-service Postgres for CI |
| `bench/accuracy`, `bench/fintech` | Accuracy runner and synthetic-bank loader |
| `SECURITY.md` | How to report a vulnerability, and the UNKNOWN-never-MASKED guarantee |

## License

Apache-2.0. See [LICENSE](LICENSE).
