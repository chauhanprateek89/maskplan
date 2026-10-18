package report

import "testing"

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

func TestRedactLiterals(t *testing.T) {
	for in, want := range map[string]string{
		`('tok_'::text || encode(SUBSTRING(sha256(('\x2e392c332e2871283932'::bytea || x)))`: `('tok_'::text || encode(SUBSTRING(sha256(('…'::bytea || x)))`,
		`concat('tok_',left(sha2(concat(0x2e392c332e2871283932abcd,x)),16))`:                `concat('tok_',left(sha2(concat(0x…,x)),16))`,
		`'carol@example.com' AS email`: `'…' AS email`,
		`'it''s short'`:                `'it''s short'`,
	} {
		if got := redactLiterals(in); got != want {
			t.Errorf("redactLiterals(%s)\n got %s\nwant %s", in, got, want)
		}
	}
}
