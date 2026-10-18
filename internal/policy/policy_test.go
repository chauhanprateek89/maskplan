package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

const valid = `version: 1
key: env:K
sources:
  app: { engine: postgres, dsn: env:D }
identities:
  agent:
    sources: [app]
    tables: [s.t]
rules:
  - { label: user.contact.email, transform: token }
  - { label: user.contact.address.postal_code, transform: prefix, params: { keep: 3 } }
overrides:
  - { column: app.s.t.nick, transform: null }
`

func load(t *testing.T, text string) (*Policy, error) {
	t.Helper()
	path := t.TempDir() + "/maskplan.yaml"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoad(t *testing.T) {
	p, err := load(t, valid)
	if err != nil {
		t.Fatal(err)
	}
	if p.Defaults.Unlabeled != Exclude || p.Defaults.FreeText != Null || p.Identities["agent"].Login != "none" ||
		p.Sources["app"].Classification != "classification.yaml" {
		t.Errorf("defaults not filled in: %+v", p)
	}
	for _, c := range []struct{ change, want string }{
		{strings.Replace(valid, "key: env:K", "key: hunter2", 1), "key must be env:VARIABLE"},
		{strings.Replace(valid, "tables: [s.t]", "tabels: [s.t]", 1), "field tabels not found"},
		{strings.Replace(valid, "transform: token", "transform: hash", 1), `unknown transform "hash"`},
		{strings.Replace(valid, "keep: 3", "keep: 9", 1), "N from 1 to 8"},
		{strings.Replace(valid, "params: { keep: 3 }", "parms: { keep: 3 }", 1), "field parms not found"},
		{strings.Replace(valid, "sources: [app]", "sources: [other]", 1), `unknown source "other"`},
		{strings.Replace(valid, "identities:\n  agent:", "identities:\n  Agent:", 1), "want a lowercase identifier"},
		{valid + "  - { label: user.contact.email, transform: null }\n", ""}, // appended to overrides: not a column
		{strings.Replace(valid, "    tables: [s.t]", "    tables: [s.t]\n    rows: { s.u: \"true\" }", 1), "rows filter for s.u, which is not in its tables"},
		{strings.Replace(valid, "    tables: [s.t]", "    tables: [s.t]\n    login: password", 1), "needs password: env:VARIABLE"},
	} {
		_, err := load(t, c.change)
		if err == nil || (c.want != "" && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("err = %v, want %q", err, c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	p, err := load(t, valid)
	if err != nil {
		t.Fatal(err)
	}
	col := func(name, label string) classification.Column {
		return classification.Column{Schema: "s", Table: "t", Column: name, Label: label}
	}
	derived := col("email_tok", "user.contact.email")
	derived.DerivedFrom = "email"
	for _, c := range []struct {
		c       classification.Column
		labeled bool
		want    string
	}{
		{col("nick", "user.name"), true, Null},                      // override before rule
		{col("email", "user.contact.email"), true, Token},           // rule
		{derived, true, Exclude},                                    // token columns: not yet
		{col("id", classification.None), true, Allow},               // labeled none
		{col("notes", classification.FreeText), true, Null},         // defaults.free_text
		{col("x", ""), false, Exclude},                              // defaults.unlabeled
		{col("iban", "user.financial.bank_account"), true, Exclude}, // no rule: fail closed
	} {
		if d := p.Decide("app", c.c, c.labeled); d.Transform != c.want {
			t.Errorf("%s: %s (%s), want %s", c.c.Column, d.Transform, d.Why, c.want)
		}
	}
	if d := p.Decide("other", col("nick", "user.name"), true); d.Transform != Exclude {
		t.Errorf("override applied to another source: %+v", d)
	}
}

func TestStarter(t *testing.T) {
	cls := &classification.File{Version: classification.Version, Source: classification.Source{Engine: "mysql"}}
	for _, c := range [][3]string{
		{"app", "customers", "user.contact.email"}, {"app", "customers", "user.name"}, {"app", "customers", "free_text"},
		{"app", "customers", "user.contact.address.postal_code"}, {"app", "customers", "none"},
		{"app", "customers", "user.health.condition"}, {"billing", "cards", "user.financial.credit_card"},
	} {
		cls.Columns = append(cls.Columns, classification.Column{Schema: c[0], Table: c[1], Column: strings.ReplaceAll(c[2], ".", "_"), Label: c[2]})
	}
	text, err := Starter(cls, "ai_agent", "classification.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := load(t, text)
	if err != nil {
		t.Fatalf("the starter does not load: %v\n%s", err, text)
	}
	id := p.Identities["ai_agent"]
	if p.Sources["app"].Engine != "mysql" || id.Password != "env:AI_AGENT_PASSWORD" || strings.Join(id.Tables, ",") != "app.customers,billing.cards" {
		t.Errorf("source %+v, identity %+v", p.Sources["app"], id)
	}
	if strings.Contains(text, "statement_timeout") || strings.Contains(text, "audit:") {
		t.Error("MySQL starter sets options MySQL does not support")
	}
	for label, want := range map[string]string{"user.contact.email": Token, "user.name": FakeName,
		"user.contact.address.postal_code": Prefix, "user.financial.credit_card": Exclude, "user.health.condition": Exclude} {
		if d := p.Decide("app", classification.Column{Schema: "app", Table: "customers", Column: "x", Label: label}, true); d.Transform != want {
			t.Errorf("%s: %s, want %s", label, d.Transform, want)
		}
	}
	if d := p.Decide("app", classification.Column{Schema: "app", Table: "customers", Column: "notes", Label: "free_text"}, true); d.Transform != Null {
		t.Errorf("free text: %s, want null", d.Transform)
	}
	if !strings.Contains(text, "free_text (1 column): decided by defaults.free_text") {
		t.Errorf("free text not explained:\n%s", text)
	}
	if !strings.Contains(text, "user.health.condition (1 column): no suggestion") {
		t.Errorf("unknown label not called out:\n%s", text)
	}
	if _, err := Starter(&classification.File{Version: 1}, "ai_agent", "c.yaml"); err == nil {
		t.Error("empty classification accepted")
	}
}
