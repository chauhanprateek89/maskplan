# maskplan

Terraform-style PII policies for Postgres and MySQL, so AI agents query masked data instead of customer records.

> **Pseudonymized is not anonymous.** maskplan replaces values with keyed tokens. Anyone holding the key can test a guessed value, and under GDPR tokenized data is still personal data. Treat it as a way to limit exposure, not as anonymization.

## Status

Pre-alpha. Nothing here is a usable tool yet. This repository currently holds the week-1 groundwork from the design:

- the [token specification](docs/token-spec.md), with a Go reference implementation and generated Postgres and MySQL SQL that produce identical tokens;
- shared test vectors that every implementation must reproduce, checked on Postgres 13 to 17 and MySQL 8.0 and 8.4 in CI;
- a [benchmark](bench/README.md) of what masking costs on a 10-million-row table.

The CLI (`maskplan scan`, `report`, `apply`) comes next, starting with a read-only `report`.

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

# Run the vectors against live databases
MASKPLAN_TEST_POSTGRES_DSN=postgres://user:pass@localhost:5432/db \
MASKPLAN_TEST_MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/db' \
go test ./internal/sqlexpr/ -v
```

| Path | Contents |
| --- | --- |
| `internal/token` | Go reference implementation of the token spec |
| `internal/sqlexpr` | Postgres and MySQL expression generators, and the live-database vector tests |
| `internal/vectors`, `testdata/vectors.json` | Shared test vectors and their generator |
| `bench/` | Benchmark harness and Docker Compose setup |
| `docs/token-spec.md` | Token specification, version 1 |

## License

Apache-2.0. See [LICENSE](LICENSE).
