package report

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// canonicalAdversarial checks the one step of the report that widens what
// counts as equal: plan canonicalization. It perturbs the reference token
// expression in every way it can think of, alone and combined, and requires
// that none of the perturbed plans canonicalizes equal to the reference.
// A positive control (the same token beside a join the planner removes)
// must canonicalize equal, so the test cannot pass by comparing nothing.
// It runs on the report fixture's tables.
func canonicalAdversarial(t *testing.T, conn *pgx.Conn) {
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	s := &pgState{ctx: ctx, tx: tx, internal: testInternal}

	type tokenSpec struct {
		col, label string
		norm       token.Normalizer
		hexLen     int
		pads       sqlexpr.Pads
	}
	_, real, _ := sqlexpr.KeySource(sqlexpr.Postgres, testInternal+".key_material", "")
	_, copied, _ := sqlexpr.KeySource(sqlexpr.Postgres, "mpt_sneaky.key_material", "")
	base := tokenSpec{"c.email", classify.Email, token.Email, 16, real}
	build := func(ts tokenSpec) string {
		x, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{Expr: ts.col, Label: ts.label, Normalizer: ts.norm, TokenHexLen: ts.hexLen}, ts.pads)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	query := func(expr, joins string) string {
		return fmt.Sprintf("SELECT v.c FROM (SELECT %s AS c FROM mpt_data.customers c%s) v", expr, joins)
	}
	canon := func(q string) string {
		got, _, err := s.explainJSON(q)
		if err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
		return got
	}
	ref := canon(query(build(base), ""))

	// Positive control: canonicalization must do its job.
	idx, err := sqlexpr.FakeIndex(sqlexpr.Postgres, sqlexpr.Column{Expr: "c.name", Label: classify.Name, Normalizer: token.Trim}, real, compile.DictionarySize)
	if err != nil {
		t.Fatal(err)
	}
	control := fmt.Sprintf("SELECT v.c FROM (SELECT fake.name AS f, %s AS c FROM mpt_data.customers c LEFT JOIN %s.names fake ON fake.i = %s) v", build(base), testInternal, idx)
	if got := canon(control); got != ref {
		t.Fatalf("positive control: the token beside a removed join does not canonicalize equal; the test would prove nothing")
	}

	// Perturbations of the token's parameters.
	params := []struct {
		name  string
		apply func(*tokenSpec)
	}{
		{"column name", func(ts *tokenSpec) { ts.col = "c.name" }},
		{"column phone", func(ts *tokenSpec) { ts.col = "c.phone" }},
		{"column expression", func(ts *tokenSpec) { ts.col = "(c.email || '')" }},
		{"column of another row", func(ts *tokenSpec) { ts.col = "(SELECT x.email FROM mpt_data.customers x WHERE x.id = c.id + 1)" }},
		{"label phone", func(ts *tokenSpec) { ts.label = classify.Phone }},
		{"label typo", func(ts *tokenSpec) { ts.label = "user.contact.emails" }},
		{"normalizer trim", func(ts *tokenSpec) { ts.norm = token.Trim }},
		{"normalizer phone", func(ts *tokenSpec) { ts.norm = token.Phone }},
		{"length 32", func(ts *tokenSpec) { ts.hexLen = 32 }},
		{"length 18", func(ts *tokenSpec) { ts.hexLen = 18 }},
		{"copied key table", func(ts *tokenSpec) { ts.pads = copied }},
		{"pads swapped", func(ts *tokenSpec) { ts.pads = sqlexpr.Pads{IPad: ts.pads.OPad, OPad: ts.pads.IPad} }},
		{"inner pad twice", func(ts *tokenSpec) { ts.pads = sqlexpr.Pads{IPad: ts.pads.IPad, OPad: ts.pads.IPad} }},
		{"mixed key tables", func(ts *tokenSpec) { ts.pads = sqlexpr.Pads{IPad: real.IPad, OPad: copied.OPad} }},
	}
	// Wrappers around the whole token expression.
	wrappers := []struct {
		name string
		wrap func(string) string
	}{
		{"coalesce raw first", func(x string) string { return "coalesce(c.email, " + x + ")" }},
		{"coalesce raw second", func(x string) string { return "coalesce(" + x + ", c.email)" }},
		{"concat raw", func(x string) string { return "(" + x + ") || c.email" }},
		{"concat empty", func(x string) string { return "(" + x + ") || ''" }},
		{"cast varchar", func(x string) string { return "(" + x + ")::varchar" }},
		{"upper", func(x string) string { return "upper(" + x + ")" }},
		{"case raw", func(x string) string { return "CASE WHEN c.id > 0 THEN " + x + " ELSE c.email END" }},
		{"nullif raw", func(x string) string { return "nullif(" + x + ", c.email)" }},
		{"extra key read", func(x string) string {
			return "(" + x + ") || (SELECT '' FROM " + testInternal + ".key_material LIMIT 1)"
		}},
		{"left of token", func(x string) string { return "left(" + x + ", 20)" }},
	}

	check := func(name, q string) {
		t.Helper()
		if canon(q) == ref {
			t.Errorf("%s: canonicalizes equal to the reference token\n%s", name, q)
		}
	}
	for _, p := range params {
		ts := base
		p.apply(&ts)
		check(p.name, query(build(ts), ""))
	}
	for _, w := range wrappers {
		check(w.name, query(w.wrap(build(base)), ""))
	}
	// Combinations, reproducible: one to three parameter changes and zero
	// to two wrappers, with and without the removable join beside them.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 150; i++ {
		ts := base
		var names []string
		for _, k := range rng.Perm(len(params))[:1+rng.Intn(3)] {
			params[k].apply(&ts)
			names = append(names, params[k].name)
		}
		x := build(ts)
		for j := rng.Intn(3); j > 0; j-- {
			w := wrappers[rng.Intn(len(wrappers))]
			x = w.wrap(x)
			names = append(names, w.name)
		}
		joins := ""
		if rng.Intn(2) == 0 {
			joins = fmt.Sprintf(" LEFT JOIN %s.names fake ON fake.i = %s", testInternal, idx)
			names = append(names, "beside a removed join")
		}
		check(strings.Join(names, " + "), query(x, joins))
	}
}
