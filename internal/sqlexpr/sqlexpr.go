// Package sqlexpr generates the Postgres and MySQL SQL expressions that
// implement the maskplan token specification (docs/token-spec.md).
//
// HMAC is computed from precomputed pads stored in a key table, so both
// engines need only built-in SHA-256 and no extension or stored function:
//
//	HMAC(K, m) = SHA256(opad || SHA256(ipad || m))
//
// The expressions must agree byte for byte with package token; the shared
// vectors in testdata/vectors.json are checked against both engines.
package sqlexpr

import (
	"fmt"

	"github.com/chauhanprateek89/maskplan/internal/token"
)

// Engine is a target database engine.
type Engine string

const (
	Postgres Engine = "postgres"
	MySQL    Engine = "mysql"
)

// Pads names the SQL expressions holding the inner and outer padded keys,
// for example "k.ipad" and "k.opad" when the key table is aliased as k.
type Pads struct {
	IPad string
	OPad string
}

// KeyJoin returns the FROM-clause fragment that joins the one-row key table
// into a masked view, and the pad expressions to use with it. The key table
// must have a primary key column id constrained to 1, so it holds at most
// one row; with no row the view returns nothing.
//
// The fragment differs by engine because each planner needs a different shape
// to stay fast:
//   - Postgres: CROSS JOIN. Scalar subqueries for the pads would make the
//     query ineligible for parallel workers (about 2.5x slower on a 4-core
//     full scan); a cross join with a one-row table keeps parallel scans and
//     hash joins between masked views.
//   - MySQL: JOIN ... ON id = 1. The primary-key lookup makes the key table a
//     "const" table, read once at planning time, so token expressions depend
//     on one base table only. Views stay mergeable and two masked views can
//     be hash-joined on a token. A plain CROSS JOIN prevents that hash join;
//     scalar subqueries make the view unmergeable, so MySQL materializes it.
//     Const substitution puts the pad values into EXPLAIN output, which MySQL
//     shows only to users with SHOW VIEW on the view: agent roles must never
//     hold SHOW VIEW.
func KeyJoin(e Engine, table, alias string) (string, Pads, error) {
	p := Pads{IPad: alias + ".ipad", OPad: alias + ".opad"}
	switch e {
	case Postgres:
		return fmt.Sprintf("CROSS JOIN %s %s", table, alias), p, nil
	case MySQL:
		return fmt.Sprintf("JOIN %s %s ON %s.id = 1", table, alias, alias), p, nil
	}
	return "", Pads{}, fmt.Errorf("unknown engine %q", e)
}

// Column describes one masked value: the SQL expression that yields it, the
// label that namespaces its tokens, and how it is normalized.
type Column struct {
	Expr       string
	Label      string
	Normalizer token.Normalizer
}

func (c Column) validate() error {
	if err := token.ValidateLabel(c.Label); err != nil {
		return err
	}
	return token.ValidateNormalizer(c.Normalizer)
}

const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Normalize returns the SQL expression for the normalized text of c.Expr.
// It applies no Unicode case folding or normalization, matching package token.
func Normalize(e Engine, c Column) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	switch e {
	case Postgres:
		v := fmt.Sprintf("(%s)::text", c.Expr)
		trimmed := fmt.Sprintf(`btrim(%s, E' \t\r\n')`, v)
		switch c.Normalizer {
		case token.Trim:
			return trimmed, nil
		case token.Email:
			// Under the "C" collation lower() maps ASCII A-Z only, which is the
			// spec, and is much faster than translate().
			return fmt.Sprintf(`lower(%s COLLATE "C")`, trimmed), nil
		case token.Phone:
			// The inner translate() deletes the ASCII digits, leaving the set of
			// every other character; the outer one deletes that set. About twice
			// as fast as regexp_replace(v, '[^0-9]', '', 'g').
			return fmt.Sprintf("translate(%s, translate(%s, '0123456789', ''), '')", v, v), nil
		}
	case MySQL:
		// Columns can have any character set and collation. Converting to
		// utf8mb4 with an explicit binary collation fixes the bytes that are
		// hashed and avoids "illegal mix of collations" with the pattern.
		v := fmt.Sprintf("CONVERT((%s) USING utf8mb4) COLLATE utf8mb4_bin", c.Expr)
		// CHAR() builds the tab, LF and CR characters so the pattern does not
		// depend on the NO_BACKSLASH_ESCAPES SQL mode.
		ws := "CHAR(9, 10, 13 USING utf8mb4)"
		pattern := fmt.Sprintf("CONVERT(CONCAT('^[ ', %s, ']+|[ ', %s, ']+$') USING utf8mb4) COLLATE utf8mb4_bin", ws, ws)
		trimmed := fmt.Sprintf("REGEXP_REPLACE(%s, %s, '')", v, pattern)
		switch c.Normalizer {
		case token.Trim:
			return trimmed, nil
		case token.Email:
			// For a pure-ASCII value (byte length equals character length)
			// LOWER() under utf8mb4_bin is exactly ASCII lowercasing. Other
			// values take 26 nested REPLACE() calls, which are case-sensitive
			// and so lowercase A-Z and nothing else, but are slower.
			chain := trimmed
			for i := 0; i < len(upper); i++ {
				chain = fmt.Sprintf("REPLACE(%s, '%c', '%c')", chain, upper[i], upper[i]+('a'-'A'))
			}
			return fmt.Sprintf("IF(LENGTH(%s) = CHAR_LENGTH(%s), LOWER(%s), %s)", v, v, trimmed, chain), nil
		case token.Phone:
			return fmt.Sprintf("REGEXP_REPLACE(%s, '[^0-9]', '')", v), nil
		}
	default:
		return "", fmt.Errorf("unknown engine %q", e)
	}
	return "", fmt.Errorf("unknown normalizer %q", c.Normalizer)
}

// mac returns the SQL expression for HMAC-SHA256 of label ':' normalized
// value: raw bytes (bytea) on Postgres, lowercase hex on MySQL, where SHA2()
// only returns hex.
func mac(e Engine, c Column, p Pads) (string, error) {
	norm, err := Normalize(e, c)
	if err != nil {
		return "", err
	}
	// Labels are validated as [a-z0-9_.], so embedding them in a literal is safe.
	switch e {
	case Postgres:
		msg := fmt.Sprintf("convert_to('%s:' || %s, 'UTF8')", c.Label, norm)
		return fmt.Sprintf("sha256(%s || sha256(%s || %s))", p.OPad, p.IPad, msg), nil
	case MySQL:
		msg := fmt.Sprintf("CONVERT(CONCAT('%s:', %s) USING utf8mb4)", c.Label, norm)
		return fmt.Sprintf("SHA2(CONCAT(%s, UNHEX(SHA2(CONCAT(%s, %s), 256))), 256)", p.OPad, p.IPad, msg), nil
	}
	return "", fmt.Errorf("unknown engine %q", e)
}

// Token returns the SQL expression for the token of c: "tok_" followed by
// the first 16 hex characters of the MAC. NULL input yields NULL.
func Token(e Engine, c Column, p Pads) (string, error) {
	m, err := mac(e, c, p)
	if err != nil {
		return "", err
	}
	switch e {
	case Postgres:
		// Hex-encode only the bytes the token keeps.
		return fmt.Sprintf("'%s' || encode(substring(%s from 1 for %d), 'hex')", token.Prefix, m, token.TokenHexLen/2), nil
	case MySQL:
		return fmt.Sprintf("CONCAT('%s', LEFT(%s, %d))", token.Prefix, m, token.TokenHexLen), nil
	}
	return "", fmt.Errorf("unknown engine %q", e)
}

// FakeIndex returns the SQL expression for the dictionary index used by
// fake_* transforms. size is baked in as a literal.
func FakeIndex(e Engine, c Column, p Pads, size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("dictionary size must be positive, got %d", size)
	}
	m, err := mac(e, c, p)
	if err != nil {
		return "", err
	}
	switch e {
	case Postgres:
		return fmt.Sprintf("((('x' || encode(substring(%s from 1 for 4), 'hex'))::bit(32)::int & 2147483647) %% %d)", m, size), nil
	case MySQL:
		return fmt.Sprintf("((CONV(LEFT(%s, 8), 16, 10) & 2147483647) %% %d)", m, size), nil
	}
	return "", fmt.Errorf("unknown engine %q", e)
}
