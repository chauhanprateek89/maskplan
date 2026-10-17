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
	"strings"

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
			return fmt.Sprintf("translate(%s, '%s', '%s')", trimmed, upper, strings.ToLower(upper)), nil
		case token.Phone:
			return fmt.Sprintf("regexp_replace(%s, '[^0-9]', '', 'g')", v), nil
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
			// MySQL has no translate(); REPLACE() is case-sensitive, so 26 nested
			// calls lowercase exactly ASCII A-Z and nothing else.
			out := trimmed
			for i := 0; i < len(upper); i++ {
				out = fmt.Sprintf("REPLACE(%s, '%c', '%c')", out, upper[i], upper[i]+('a'-'A'))
			}
			return out, nil
		case token.Phone:
			return fmt.Sprintf("REGEXP_REPLACE(%s, '[^0-9]', '')", v), nil
		}
	default:
		return "", fmt.Errorf("unknown engine %q", e)
	}
	return "", fmt.Errorf("unknown normalizer %q", c.Normalizer)
}

// MACHex returns the SQL expression for the lowercase hex HMAC-SHA256 of
// label ':' normalized value, using the pads in p.
func MACHex(e Engine, c Column, p Pads) (string, error) {
	norm, err := Normalize(e, c)
	if err != nil {
		return "", err
	}
	// Labels are validated as [a-z0-9_.], so embedding them in a literal is safe.
	switch e {
	case Postgres:
		msg := fmt.Sprintf("convert_to('%s:' || %s, 'UTF8')", c.Label, norm)
		return fmt.Sprintf("encode(sha256(%s || sha256(%s || %s)), 'hex')", p.OPad, p.IPad, msg), nil
	case MySQL:
		msg := fmt.Sprintf("CONVERT(CONCAT('%s:', %s) USING utf8mb4)", c.Label, norm)
		return fmt.Sprintf("SHA2(CONCAT(%s, UNHEX(SHA2(CONCAT(%s, %s), 256))), 256)", p.OPad, p.IPad, msg), nil
	}
	return "", fmt.Errorf("unknown engine %q", e)
}

// Token returns the SQL expression for the token of c: "tok_" followed by
// the first 16 hex characters of the MAC. NULL input yields NULL.
func Token(e Engine, c Column, p Pads) (string, error) {
	mac, err := MACHex(e, c, p)
	if err != nil {
		return "", err
	}
	switch e {
	case Postgres:
		return fmt.Sprintf("'%s' || left(%s, %d)", token.Prefix, mac, token.TokenHexLen), nil
	case MySQL:
		return fmt.Sprintf("CONCAT('%s', LEFT(%s, %d))", token.Prefix, mac, token.TokenHexLen), nil
	}
	return "", fmt.Errorf("unknown engine %q", e)
}

// FakeIndex returns the SQL expression for the dictionary index used by
// fake_* transforms. size is baked in as a literal.
func FakeIndex(e Engine, c Column, p Pads, size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("dictionary size must be positive, got %d", size)
	}
	mac, err := MACHex(e, c, p)
	if err != nil {
		return "", err
	}
	switch e {
	case Postgres:
		return fmt.Sprintf("((('x' || left(%s, 8))::bit(32)::int & 2147483647) %% %d)", mac, size), nil
	case MySQL:
		return fmt.Sprintf("((CONV(LEFT(%s, 8), 16, 10) & 2147483647) %% %d)", mac, size), nil
	}
	return "", fmt.Errorf("unknown engine %q", e)
}
