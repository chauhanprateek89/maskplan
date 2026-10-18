# Security

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: on this repository, open **Security → Report a vulnerability**. Please do not open a public issue. Include the PostgreSQL or MySQL version, the schema and grants that reproduce the problem, and the report output.

Fixes for confirmed issues are released with a note in the release and in `NOTES.md` describing what was wrong and how it was found.

## Design guarantee: UNKNOWN, never MASKED

`maskplan report` reports a column as `MASKED` only when it has verified that the role reads that column as maskplan tokens and nothing else. Any path it cannot trace is `UNKNOWN`, which fails the report like `RAW`.

A report that says `MASKED` while a role can read raw values is a security vulnerability in maskplan, whatever the cause: an unusual view, a server version, a managed service's roles. Please report it as one. A report that says `UNKNOWN` for a path that is in fact safe is a bug, not a vulnerability.

The same applies to `KEY`: a role that can read the token key material, or the key appearing anywhere every role can read it, must be reported.

## Scope

maskplan limits exposure; it does not anonymize. Tokens are pseudonyms: anyone with the key can test guessed values, and tokenized data is still personal data under GDPR. Reports about that property of the design are welcome as discussion, not as vulnerabilities. See [docs/token-spec.md](docs/token-spec.md) and [docs/report.md](docs/report.md) for what is and is not checked.

## What maskplan does to your database

`scan` and `report` only read: both run in read-only transactions with statement timeouts, and `scan` stores no sampled values. Run them as a role that can read the catalog, on a replica if you prefer.
