package report

import (
	"strings"
	"testing"
)

// TestTokenLength covers how each supported server version deparses the
// substring call in a token, taken from real EXPLAIN output.
func TestTokenLength(t *testing.T) {
	for _, c := range []struct{ version, output string }{
		{"14+", `('tok_'::text || encode(SUBSTRING(sha256(($0 || sha256(($1 || convert_to(('user.contact.email:'::text || lower((btrim(c.email, ' '::text))::text)), 'UTF8'::name))))) FROM 1 FOR 8), 'hex'::text))`},
		{"13", `('tok_'::text || encode("substring"(sha256(($0 || sha256(($1 || convert_to(('user.contact.email:'::text || lower((btrim(c.email, ' '::text))::text)), 'UTF8'::name))))), 1, 8), 'hex'::text))`},
	} {
		m := tokenLenRe.FindStringSubmatch(c.output)
		if m == nil || m[1] != "8" {
			t.Errorf("PostgreSQL %s: length %v, want 8", c.version, m)
		}
		if l := tokenLabelRe.FindStringSubmatch(c.output); l == nil || l[1] != "user.contact.email" {
			t.Errorf("PostgreSQL %s: label %v", c.version, l)
		}
	}
}

func TestRedactSQL(t *testing.T) {
	const key = "2e392c332e2871283932"
	for _, c := range []struct {
		d       dialect
		in, out string // out "" means it must not lex
	}{
		// Postgres: standard strings, '' escapes, backslashes taken literally.
		{dialectPostgres, `('tok_'::text || encode(SUBSTRING(sha256(('\x` + key + `'::bytea || x)))`, `('tok_'::text || encode(SUBSTRING(sha256(('…'::bytea || x)))`},
		{dialectPostgres, `'carol@example.com' AS email`, `'…' AS email`},
		{dialectPostgres, `'it''s'`, `'it''s'`},
		{dialectPostgres, `'a''` + key + `'`, `'…'`},
		{dialectPostgres, `'\' || '` + key + `'`, `'\' || '…'`},
		// E'' strings: a backslash escapes the quote.
		{dialectPostgres, `E'\'` + key + `' || x`, `E'…' || x`},
		{dialectPostgres, `E' \t\r\n'`, `E' \t\r\n'`},
		// Dollar quoting, with and without a tag; $1 is a parameter.
		{dialectPostgres, `$$` + key + `$$::bytea`, `'…'::bytea`},
		{dialectPostgres, `$k$it's ` + key + `$k$ || $1`, `'…' || $1`},
		{dialectPostgres, `$$short$$`, `$$short$$`},
		{dialectPostgres, `a$b$ || 'x'`, `a$b$ || 'x'`},
		// Prefixed literals and quoted identifiers.
		{dialectPostgres, `U&'` + key + `' || "it''s ` + key + `"`, `U&'…' || "it''s ` + key + `"`},
		{dialectPostgres, `X'` + key + `'`, `X'…'`},
		// Comments go, nested on Postgres.
		{dialectPostgres, `x /* a /* ` + key + ` */ b */ || y -- ` + key, `x   || y `},
		// What does not lex shows nothing.
		{dialectPostgres, `'unterminated ` + key, ""},
		{dialectPostgres, `$$` + key, ""},
		{dialectPostgres, `/* ` + key, ""},
		// MySQL: backslash escapes in both quotes, hex numbers, introducers.
		{dialectMySQL, `concat('tok_',left(sha2(concat(0x` + key + `abcd,x)),16))`, `concat('tok_',left(sha2(concat(0x…,x)),16))`},
		{dialectMySQL, `'it\'s ` + key + `'`, `'…'`},
		{dialectMySQL, `"` + key + `" AS c`, `'…' AS c`},
		{dialectMySQL, "_utf8mb4'" + key + "' AND `col` = X'" + key + "'", "_utf8mb4'…' AND `col` = X'…'"},
		{dialectMySQL, `x # ` + key, `x `},
		{dialectMySQL, `'a\'`, ""},
	} {
		got, ok := redactSQL(c.d, c.in)
		switch {
		case c.out == "" && ok:
			t.Errorf("redactSQL(%s) = %s, want it refused", c.in, got)
		case c.out != "" && (!ok || got != c.out):
			t.Errorf("redactSQL(%s)\n got %s (%v)\nwant %s", c.in, got, ok, c.out)
		}
		if ok && strings.Contains(got, key[:16]) && !strings.Contains(c.in, `"it''s`) {
			t.Errorf("redactSQL(%s) shows the key: %s", c.in, got)
		}
	}
	if got := showExpr(false, dialectPostgres, "'"+key+"'"); got != hiddenExpr {
		t.Errorf("expressions are shown by default: %s", got)
	}
	if got := showExpr(true, dialectPostgres, "'"+key); got != unreadableExpr {
		t.Errorf("an unreadable expression is shown: %s", got)
	}
}
