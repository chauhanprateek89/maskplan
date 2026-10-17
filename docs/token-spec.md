# Token specification, version 1

A token replaces a sensitive value with a stable, keyed pseudonym. The same value under the same label and key produces the same token in Postgres, MySQL and Go, so masked columns can still be joined, grouped and counted.

Tokens are pseudonyms, not anonymous data. Anyone holding the key can test a guessed value. Under GDPR, tokenized data is still personal data.

## Algorithm

```
token(key, label, normalizer, value) =
    NULL                                               if value is NULL
    "tok_" || hex(HMAC-SHA256(key, label || ":" || normalize(value)))[0:L]
```

- `hex` is lowercase hexadecimal. `L` is the token length in hex characters: 16 (64 bits) by default, or any even number from 16 to 64, set per label. A longer token extends the shorter one: the 16-character token is a prefix of the 24-character token for the same value.
- The message is the UTF-8 bytes of the label, a colon, and the normalized value.
- Empty string is a value, not NULL, and gets a token.

### Token length and collisions

Two different values can share a truncated token, and a shared token is a false join match. By the birthday bound, n distinct values under one label collide with probability about n² / 2^(4L+1):

| Distinct values | L = 16 (64 bits) | L = 24 (96 bits) |
| --- | --- | --- |
| 10^7 | 3 × 10^-6 | 6 × 10^-16 |
| 10^9 | 3% | 6 × 10^-12 |

Use `L = 24` for labels that can exceed about 10^8 distinct values, such as event or transaction identifiers. Changing a label's length changes every token under it, so choose it before agents depend on the tokens.

### Input types

Tokens are defined over text. Integer columns are hashed as their decimal text, which is identical on both engines; decimal columns include their scale (`1.0` and `1` differ). Binary columns (`bytea`, `BINARY`, `VARBINARY`, `BLOB`) are not supported in version 1: MySQL would reinterpret their bytes as `utf8mb4`, substituting or rejecting invalid sequences, and the result would not match the Go reference. `policy test` must reject a token rule on a binary column.

### Labels

A label is a lowercase dotted identifier matching `^[a-z0-9_]+(\.[a-z0-9_]+)*$`, for example `user.contact.email`. Labels never contain a colon, so the separator is unambiguous. The label namespaces tokens: the same characters under `user.contact.email` and `user.contact.phone` produce different tokens.

### Normalizers

Normalization works on bytes. It never applies Unicode case folding or Unicode normalization (NFC/NFD); values are hashed as given. MySQL has no Unicode normalization function, so no portable implementation could apply one.

| Normalizer | Steps | Example |
| --- | --- | --- |
| `trim` | Remove space (0x20), tab (0x09), LF (0x0A) and CR (0x0D) from both ends. Nothing else is removed: no-break space, vertical tab and form feed are kept. Internal whitespace is not collapsed. | `" a  b\r\n"` → `"a  b"` |
| `email` | `trim`, then map ASCII `A`–`Z` to `a`–`z`. Every other character, including `É`, is unchanged. | `" Émile@Example.FR"` → `"Émile@example.fr"` |
| `phone` | Keep ASCII digits `0`–`9` only. No country inference and no E.164 formatting. | `"+353 (0)1 234-5678"` → `"353012345678"` |

Consequences to document for users:

- `"+353 1 234 5678"` and `"01 234 5678"` are the same number but produce different tokens. E.164 normalization belongs in ETL code using the Go library, not in SQL.
- `é` written as U+00E9 and as `e` + U+0301 produce different tokens.
- Numbers are hashed as their decimal text. Integer columns give the same text in every engine. Decimal columns include their scale, so `1.0` and `1` produce different tokens; declare the same scale in both engines if tokens must match.

### Fake-value index

`fake_*` transforms pick a display value from a dictionary of size `N`:

```
fake_index = (big_endian_uint32(MAC[0:4]) & 0x7fffffff) mod N
```

Many people share one fake value, so fake values are cosmetic and are never join keys. Use `token` to join.

## Keys and pads

The key is any byte string, supplied at `apply` time from an environment variable or a secret manager. SQL computes HMAC from two precomputed pads instead of the key:

```
K'   = SHA256(key) if len(key) > 64, else key
K0   = K' zero-padded to 64 bytes
ipad = K0 xor 0x36 (each byte)
opad = K0 xor 0x5c (each byte)
HMAC(key, m) = SHA256(opad || SHA256(ipad || m))
```

This is standard HMAC (RFC 2104), so the output equals `crypto/hmac`, `pgcrypto`'s `hmac()` and any other implementation. Computing it from pads means both engines need only their built-in SHA-256: no extension and no stored function.

The pads are key material. They live in a one-row table, `maskplan_internal.key_material (id, ipad, opad)` with `id` constrained to 1, that agent roles cannot read. Views join it with the view owner's rights. Pads never appear as literals in SQL, because Postgres exposes every view definition through `pg_views` and every function body through `pg_proc`, and MySQL writes view DDL to the binary log.

How a view reads the key table depends on the engine, because each planner needs a different shape to stay fast (`sqlexpr.KeySource`; measurements in `bench/README.md`):

| Engine | Pads read as | Why |
| --- | --- | --- |
| Postgres | `(SELECT ipad FROM maskplan_internal.key_material)`, likewise `opad` | Uncorrelated scalar subqueries become InitPlans, evaluated once and passed to parallel workers, and the plan does not depend on the key table's statistics. A `CROSS JOIN` with the analyzed one-row table puts the key table on the outer side of a nested loop, which cannot run in parallel. |
| MySQL | `JOIN maskplan_internal.key_material k ON k.id = 1` | The primary-key lookup makes the key table a const table, read once at planning time. Views stay mergeable and two masked views hash-join on a token. A plain `CROSS JOIN` prevents the hash join; scalar subqueries make the view unmergeable, so MySQL materializes it in full. |

On Postgres, column-masking views are created without `security_barrier`. The option stops a view from being flattened into the outer query, so aggregates and joins cannot be pushed into parallel workers: every row would cross the Gather, and at real costs the planner chooses a serial plan instead (2.6x slower on a 10M-row scan). It protects row filters: without it, a function in the agent's `WHERE` clause could run on rows the view's own `WHERE` would remove. A view that only masks columns removes no rows, and the outer query can reference only its token and passthrough columns, so such a function never sees a raw masked value. Views that apply a row filter keep `security_barrier` and pay the cost.

Both claims are regression-tested on every CI matrix version (`internal/sqlexpr/plan_test.go`): a `plpgsql` function that reports every argument it receives, called in the `WHERE` clause of a column-only view, never sees a raw email; called on a row-filtered view, it never sees a filtered-out row. The same file asserts the plan shapes the performance depends on: on Postgres a partial aggregate in parallel workers with the pads read by InitPlans and the key table never the outer side of a nested loop; on MySQL a `const` access to the key table, merged views, and a hash join between two masked views.

Because MySQL substitutes const-table values into the plan, the pads appear in `EXPLAIN` output and in the optimizer trace for anyone allowed to see those. Checked on MySQL 8.0.46 with a role holding only `SELECT` on a masked view:

| Attempt | Result |
| --- | --- |
| `SELECT` from the view | Returns tokens |
| `SELECT` from `key_material` | Denied |
| `EXPLAIN`, `EXPLAIN ANALYZE` | Denied: "lacking privileges for underlying table" |
| Optimizer trace | Empty, `INSUFFICIENT_PRIVILEGES = 1` |
| `SHOW CREATE VIEW` | Denied |
| `information_schema.VIEWS.VIEW_DEFINITION` | Empty |

Granting `SHOW VIEW` as well still leaves `EXPLAIN` and the trace denied; `SHOW CREATE VIEW` then works but shows only the reference to `key_material`, never key bytes. The pads are therefore exposed only to users with privileges on the key table or the base tables, which agent roles never get; `report` flags any such grant. CI should repeat this check on MySQL 8.4 and on each managed service.

Rotating the key rewrites the key table. Tokens made with the old key no longer match, by design.

### Key table invariants

The key table must hold exactly one row. If it is empty, nothing fails loudly: on Postgres the scalar subqueries return NULL and every token is NULL; on MySQL the join finds no key row and the views return no rows. Both fail safe (no raw data, token joins match nothing) but are invisible, so:

- `apply` asserts exactly one key row after writing it, and refuses to finish otherwise.
- `report` verifies the key table of every source it inspects and flags an empty or multi-row table.
- Tests pin the empty-table behavior on both engines (`TestEmptyKeyTable*`), so a change in it is noticed.

### Preflight requirements

- **Postgres `server_encoding` must be `UTF8`.** Under `SQL_ASCII`, `convert_to(..., 'UTF8')` does not convert: stored bytes are hashed as they are, may not be UTF-8, and would not match Go. `preflight` refuses to compile tokens for such a database.
- **No binary columns under a token rule** (see Input types).

### Materialized token columns (design note)

A token lookup (`WHERE email = 'tok_...'`) hashes every row, because tokens have no index: about 16 s on 10M rows on Postgres (see `bench/README.md`). The fix is a stored, indexed `*_tok` column, and its shape is constrained by the same rule as the views, that no key bytes may appear in SQL text:

- A generated column cannot read another table, so it cannot read the key table.
- A function with the key embedded would expose it through `pg_proc` (Postgres) or the binary log (MySQL).

The viable shape is a trigger. The trigger function is owned by the key-table owner, reads `maskplan_internal.key_material` at runtime and writes the token into `email_tok` on insert and update. On Postgres it is `SECURITY DEFINER` with `EXECUTE` revoked from `PUBLIC`; trigger functions cannot be called directly, so it is not a hashing oracle. On MySQL triggers run with their definer's rights by default. The view then selects `email_tok` instead of computing the token, and an index on `email_tok` makes lookups and joins index-backed. Costs: writes pay for one HMAC per tokenized column, the base table grows by one column per token, and key rotation must rewrite every token column.

## SQL implementations

Generated by `internal/sqlexpr`; shown here for value expression `v`, label `user.contact.email` and pad expressions `IPAD`, `OPAD`.

### Postgres (13+)

| Step | Expression |
| --- | --- |
| trim | `btrim((v)::text, E' \t\r\n')` |
| email | `lower(<trim> COLLATE "C")`; under the `C` collation `lower()` maps ASCII only |
| phone | `translate(t, translate(t, '0123456789', ''), '')` where `t` is `(v)::text` |
| MAC | `sha256(OPAD \|\| sha256(IPAD \|\| convert_to('user.contact.email:' \|\| <norm>, 'UTF8')))` |
| token | `'tok_' \|\| encode(substring(<MAC> from 1 for L/2), 'hex')` (L/2 bytes for L hex characters) |

`convert_to(..., 'UTF8')` hashes UTF-8 bytes whatever the server encoding is.

### MySQL (8.0+)

| Step | Expression |
| --- | --- |
| value | `CONVERT((v) USING utf8mb4) COLLATE utf8mb4_bin`, which fixes the bytes whatever the column's character set and avoids collation conflicts |
| trim | `REGEXP_REPLACE(<value>, <pattern>, '')`, with the pattern `^[ \t\n\r]+\|[ \t\n\r]+$` built from `CHAR(9, 10, 13)` so it does not depend on `NO_BACKSLASH_ESCAPES` |
| email | `IF(LENGTH(<value>) = CHAR_LENGTH(<value>), LOWER(<trim>), <26 nested REPLACE>)`. For pure-ASCII values `LOWER()` is exactly ASCII lowercasing; other values use case-sensitive `REPLACE()` for `A`–`Z` only |
| phone | `REGEXP_REPLACE(<value>, '[^0-9]', '')` |
| MAC (hex) | `SHA2(CONCAT(OPAD, UNHEX(SHA2(CONCAT(IPAD, CONVERT(CONCAT('user.contact.email:', <norm>) USING utf8mb4)), 256))), 256)` |
| token | `CONCAT('tok_', LEFT(<MAC>, L))` |

## Conformance

`testdata/vectors.json` holds the shared vectors: label, normalizer, token length, input (a JSON string, so whitespace and Unicode are unambiguous, or `null`), key (hex), expected token and expected fake index for a 4096-entry dictionary. The file is generated from the Go reference (`go run ./cmd/genvectors`) and is checked independently by `scripts/check_vectors.py`, which uses Python's `hmac` module and shares no code with the Go reference.

An implementation conforms if it reproduces every vector exactly. CI checks Go on every commit, and the generated SQL on Postgres 13, 14, 15, 16 and 17 and MySQL 8.0 and 8.4.

`testdata/vectors.json` is frozen at the `spec-v1` tag. Changing anything in this document that changes a token requires a new spec version and a new vectors file; the Python check fails on any drift between the file and the spec.
