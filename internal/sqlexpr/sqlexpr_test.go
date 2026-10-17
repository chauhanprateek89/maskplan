package sqlexpr

import (
	"strings"
	"testing"

	"github.com/chauhanprateek89/maskplan/internal/token"
)

var testPads = Pads{IPad: "k.ipad", OPad: "k.opad"}

func TestRejectsUnsafeLabels(t *testing.T) {
	for _, e := range []Engine{Postgres, MySQL} {
		col := Column{Expr: "x", Label: "user.email'; DROP TABLE users; --", Normalizer: token.Email}
		if _, err := Token(e, col, testPads); err == nil {
			t.Errorf("%s: unsafe label accepted", e)
		}
	}
}

func TestRejectsUnknownEngineAndNormalizer(t *testing.T) {
	if _, err := Token("oracle", Column{Expr: "x", Label: "a", Normalizer: token.Trim}, testPads); err == nil {
		t.Error("unknown engine accepted")
	}
	if _, err := Token(Postgres, Column{Expr: "x", Label: "a", Normalizer: "upper"}, testPads); err == nil {
		t.Error("unknown normalizer accepted")
	}
	if _, err := FakeIndex(Postgres, Column{Expr: "x", Label: "a", Normalizer: token.Trim}, testPads, 0); err == nil {
		t.Error("zero dictionary size accepted")
	}
}

// The MySQL email expression must lowercase exactly the 26 ASCII letters.
func TestMySQLEmailReplacesAllASCIILetters(t *testing.T) {
	expr, err := Normalize(MySQL, Column{Expr: "x", Label: "a", Normalizer: token.Email})
	if err != nil {
		t.Fatal(err)
	}
	for c := 'A'; c <= 'Z'; c++ {
		want := "'" + string(c) + "', '" + strings.ToLower(string(c)) + "'"
		if !strings.Contains(expr, want) {
			t.Errorf("missing REPLACE for %c", c)
		}
	}
	if n := strings.Count(expr, "REPLACE("); n != 26+1 { // 26 REPLACE + 1 REGEXP_REPLACE
		t.Errorf("got %d REPLACE( occurrences, want 27", n)
	}
}

func TestNoKeyMaterialInExpressions(t *testing.T) {
	// Expressions reference the pad columns by name only; key bytes never
	// appear in generated SQL, which on Postgres is readable via pg_views.
	for _, e := range []Engine{Postgres, MySQL} {
		expr, err := Token(e, Column{Expr: "u.email", Label: "user.contact.email", Normalizer: token.Email}, testPads)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(expr, "k.ipad") || !strings.Contains(expr, "k.opad") {
			t.Errorf("%s: pads not referenced: %s", e, expr)
		}
	}
}
