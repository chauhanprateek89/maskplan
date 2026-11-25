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

// The key-table warning states what the views actually do with a key table
// that does not hold exactly one row: Postgres reads the pads with scalar
// subqueries, MySQL joins the key row on id = 1 (sqlexpr.KeySource).
func TestKeyRowsWarning(t *testing.T) {
	for _, c := range []struct {
		d         dialect
		n         int
		want, not string
	}{
		{dialectPostgres, 0, "every token is NULL", ""},
		{dialectPostgres, 2, "more than one row returned by a subquery", "every token is NULL"},
		{dialectMySQL, 0, "return no rows", "every token is NULL"},
		{dialectMySQL, 3, "repeat", "every token is NULL"},
	} {
		got := keyRowsWarning(c.d, c.n)
		if !strings.Contains(got, c.want) || (c.not != "" && strings.Contains(got, c.not)) {
			t.Errorf("%v with %d rows: %q, want it to say %q", c.d, c.n, got, c.want)
		}
	}
}

// Every privilege on the key table is a KEY finding, and the finding says
// what the privilege allows.
func TestKeyPrivilegePaths(t *testing.T) {
	for _, c := range []struct {
		privs []string
		want  []string // one entry per finding, each a substring
	}{
		{[]string{"SELECT"}, []string{"can read the token key material"}},
		{[]string{"INSERT"}, []string{"holds INSERT on the token key material as x: it can replace the key"}},
		{[]string{"SELECT", "UPDATE", "TRIGGER"}, []string{"can read", "holds UPDATE, TRIGGER on the token key material as x: it can replace the key with one it knows, so every token computed afterwards can be reversed by guessing; a trigger it creates"}},
		{[]string{"REFERENCES"}, []string{"holds REFERENCES on the token key material as x: no role but the one running apply"}},
	} {
		got := keyPrivilegePaths(c.privs, "as x")
		if len(got) != len(c.want) {
			t.Errorf("%v: %d findings %q, want %d", c.privs, len(got), got, len(c.want))
			continue
		}
		for i := range got {
			if !strings.Contains(got[i], c.want[i]) {
				t.Errorf("%v: finding %q, want it to contain %q", c.privs, got[i], c.want[i])
			}
		}
	}
}

// The MySQL grant tables are evaluated by hand, so the evaluation of
// privileges other than SELECT is tested without a server too; the
// fixtures in mysql_test.go check it against MySQL itself.
func TestPrivPathsMySQL(t *testing.T) {
	a := myAccount{user: "agent", host: "%"}
	r := myAccount{user: "writer", host: "%", how: "granted role", chain: "'agent'@'%' > 'writer'@'%'"}
	const db, tbl = "maskplan_internal", "key_material"
	s := &myState{
		accounts: []myAccount{a, r},
		userRows: map[[2]string]map[string]string{a.key(): {"Select_priv": "N"}, r.key(): {"Trigger_priv": "Y"}},
		dbRows:   []myDBGrant{{account: a.key(), pattern: `maskplan\_internal`, privs: map[string]bool{"Delete": true}}},
		tblRows:  []myTableGrant{{account: a.key(), db: db, name: tbl, privileges: "Insert,Drop"}},
		colRows:  []myTableGrant{{account: a.key(), db: db, name: tbl, column: "ipad", privileges: "Update"}},
	}
	for _, c := range []struct {
		priv, column string
		want         []string
	}{
		{"Select", "ipad", nil},
		{"Insert", "", []string{"INSERT on the table granted to 'agent'@'%'"}},
		{"Update", "", nil},
		{"Update", "ipad", []string{"UPDATE on the column granted to 'agent'@'%'"}},
		{"Delete", "", []string{"DELETE on `maskplan\\_internal`.* granted to 'agent'@'%'"}},
		{"Drop", "", []string{"DROP on the table granted to 'agent'@'%'"}},
		{"Trigger", "", []string{"global TRIGGER granted to 'writer'@'%' (granted role: 'agent'@'%' > 'writer'@'%')"}},
		{"References", "id", nil},
	} {
		got := s.privPaths(db, tbl, c.column, c.priv)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s on %q: %q, want %q", c.priv, c.column, got, c.want)
		}
	}
}
