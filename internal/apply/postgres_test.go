package apply

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/report"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

const internal = "mpa_internal"

var key = []byte("apply-test-key-0123456789abcdef!")

func testPolicy() *policy.Policy {
	p := &policy.Policy{
		Version: policy.Version,
		Key:     "env:MPA_KEY",
		Sources: map[string]policy.Source{"app": {Engine: "postgres", DSN: "env:X"}},
		Identities: map[string]policy.Identity{
			"mpa_agent": {Sources: []string{"app"}, Tables: []string{"mpa_app.users", "mpa_app.tickets"}, Login: "password", Password: "env:MPA_PW",
				Limits: policy.Limits{Connections: 3, StatementTimeout: "30s"}},
			"mpa_support": {Sources: []string{"app"}, Tables: []string{"mpa_app.tickets"},
				Rows: map[string]string{"mpa_app.tickets": "b.tenant_id = 1"}},
		},
		Rules: []policy.Rule{
			{Label: classify.Email, Transform: policy.Token},
			{Label: classify.Phone, Transform: policy.Token},
			{Label: classify.Name, Transform: policy.FakeName},
			{Label: classify.BirthDate, Transform: policy.GeneralizeYear},
			{Label: classify.PostalCode, Transform: policy.Prefix, Params: map[string]any{"keep": 3}},
			{Label: classify.Secret, Transform: policy.Exclude},
		},
		Overrides: []policy.Override{{Column: "app.mpa_app.tickets.requester_email", Transform: policy.FakeEmail}},
	}
	if err := p.Validate(); err != nil {
		panic(err)
	}
	return p
}

func testClassification() *classification.File {
	f := &classification.File{Version: classification.Version}
	add := func(table string, cols ...string) {
		for i := 0; i < len(cols); i += 2 {
			f.Columns = append(f.Columns, classification.Column{Schema: "mpa_app", Table: table, Column: cols[i], Label: cols[i+1]})
		}
	}
	add("users", "id", classify.None, "email", classify.Email, "full_name", classify.Name, "birth_date", classify.BirthDate,
		"postcode", classify.PostalCode, "phone", classify.Phone, "country", classify.None, "password_hash", classify.Secret,
		"notes", classify.FreeText)
	add("tickets", "id", classify.None, "tenant_id", classify.None, "requester_email", classify.Email, "body", classify.FreeText)
	return f
}

func TestApplyPostgres(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	drop := func() {
		for _, q := range []string{"DROP SCHEMA IF EXISTS mpa_app, mpa_agent, mpa_support, " + internal + " CASCADE",
			"DROP ROLE IF EXISTS mpa_agent", "DROP ROLE IF EXISTS mpa_support", "DROP ROLE IF EXISTS mpa_squatter"} {
			conn.Exec(ctx, q)
		}
	}
	drop()
	if os.Getenv("MPA_KEEP") == "" {
		t.Cleanup(drop)
	}
	for _, q := range []string{
		"CREATE SCHEMA mpa_app",
		`CREATE TABLE mpa_app.users (id int PRIMARY KEY, email text, full_name text, birth_date date, postcode text,
			phone text, country text, password_hash text, notes text, nickname text)`,
		"INSERT INTO mpa_app.users VALUES (1, 'Alice@Example.com', 'Alice Byrne', '1990-06-15', 'D02 X285', '+353 1 234 5678', 'IE', 'x', 'call after 5', 'ali'), (2, 'bob@example.com', 'Bob Ryan', '1985-01-02', 'T12 Y7K2', '01 234 5679', 'IE', 'y', NULL, 'bob')",
		"CREATE TABLE mpa_app.tickets (id int PRIMARY KEY, tenant_id int, requester_email text, body text)",
		"INSERT INTO mpa_app.tickets VALUES (1, 1, 'alice@example.com', 'hello'), (2, 2, 'eve@example.com', 'other tenant')",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	p := testPolicy()
	cls := testClassification()
	passwords := map[string]string{"mpa_agent": "mpa-agent-pw"}
	plan, err := PlanPostgres(ctx, conn, p, "app", cls, key, passwords, internal)
	if err != nil {
		t.Fatal(err)
	}
	var printed bytes.Buffer
	plan.Print(&printed)
	ipad, opad := token.Pads(key)
	for _, secret := range []string{fmt.Sprintf("%x", ipad)[:16], fmt.Sprintf("%x", opad)[:16], string(key), "mpa-agent-pw"} {
		if strings.Contains(printed.String(), secret) {
			t.Fatalf("the plan contains a secret (%q)", secret)
		}
	}
	if err := RunPostgres(ctx, conn, plan); err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + printed.String())

	check := func(t *testing.T, identity string, withPolicy, pass bool, want ...string) {
		t.Helper()
		opts := report.Options{Schemas: []string{"mpa_app", identity}, InternalSchema: internal}
		if withPolicy {
			opts.Policy = p
		}
		r, err := report.Postgres(ctx, conn, identity, cls, opts)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		r.WriteText(&b)
		if r.Failed() == pass {
			t.Errorf("%s (policy %v): Failed() = %v, want %v\n%s", identity, withPolicy, r.Failed(), !pass, b.String())
		}
		for _, w := range want {
			if !strings.Contains(b.String(), w) {
				t.Errorf("%s (policy %v): report does not contain %q\n%s", identity, withPolicy, w, b.String())
			}
		}
	}
	t.Run("report passes right after apply", func(t *testing.T) {
		for _, withPolicy := range []bool{false, true} {
			check(t, "mpa_agent", withPolicy, true,
				"MASKED    mpa_agent.users.email", "maskplan fake_name of mpa_app.users.full_name",
				"maskplan generalize_year of mpa_app.users.birth_date", "maskplan prefix of mpa_app.users.postcode",
				"maskplan token of mpa_app.users.phone", "maskplan fake_email of mpa_app.tickets.requester_email")
		}
		check(t, "mpa_support", false, true, "maskplan fake_email of mpa_app.tickets.requester_email",
			"WARN      view mpa_support.tickets", "shows only rows where (b.tenant_id = 1); not checked against a policy")
		check(t, "mpa_support", true, true, "maskplan fake_email of mpa_app.tickets.requester_email")
	})

	t.Run("agent reads masked values", func(t *testing.T) {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Password = "mpa_agent", "mpa-agent-pw"
		agent, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer agent.Close(ctx)
		rows, err := agent.Query(ctx, "SELECT * FROM users ORDER BY id") // search_path is the identity's schema
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowToMap)
		if err != nil {
			t.Fatal(err)
		}
		cols := slices.Sorted(maps.Keys(got[0]))
		if want := []string{"birth_date", "country", "email", "full_name", "id", "notes", "phone", "postcode"}; !slices.Equal(cols, want) {
			t.Errorf("columns %v, want %v (secret and unlabeled columns excluded)", cols, want)
		}
		alice := got[0]
		raw := "Alice@Example.com"
		if alice["email"] != *token.Token(key, classify.Email, token.Email, &raw) {
			t.Errorf("email %v is not the token the spec gives", alice["email"])
		}
		if !slices.Contains(compile.Names(), alice["full_name"].(string)) {
			t.Errorf("full_name %v is not a dictionary name", alice["full_name"])
		}
		if d := alice["birth_date"].(time.Time); d.Format("2006-01-02") != "1990-01-01" {
			t.Errorf("birth_date %v, want 1990-01-01", d)
		}
		if alice["postcode"] != "D02" || alice["notes"] != nil || alice["country"] != "IE" {
			t.Errorf("postcode %v, notes %v, country %v", alice["postcode"], alice["notes"], alice["country"])
		}
		for _, q := range []string{"SELECT email FROM mpa_app.users", "SELECT ipad FROM " + internal + ".key_material", "SELECT name FROM " + internal + ".names"} {
			if _, err := agent.Exec(ctx, q); err == nil {
				t.Errorf("agent can run %s", q)
			}
		}
	})

	t.Run("row filter", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var n int
		var email string
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE mpa_support"); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM mpa_support.tickets").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, "SELECT requester_email FROM mpa_support.tickets").Scan(&email); err != nil {
			t.Fatal(err)
		}
		if n != 1 || !strings.HasSuffix(email, "@example.invalid") {
			t.Errorf("mpa_support sees %d rows, email %q; want 1 row and a fake email", n, email)
		}
	})

	// Bypasses of the row filter: the columns stay masked, so only the
	// comparison with the policy catches them.
	var created string
	for _, s := range plan.Statements {
		if strings.HasPrefix(s.SQL, `CREATE VIEW "mpa_support"."tickets"`) {
			created = s.SQL
		}
	}
	const filter = "\nWHERE b.tenant_id = 1"
	if !strings.Contains(created, filter) || !strings.Contains(created, " WITH (security_barrier)") {
		t.Fatalf("unexpected view definition:\n%s", created)
	}
	for _, c := range []struct{ name, sql string }{
		{"filter dropped", strings.Replace(strings.Replace(created, filter, "", 1), " WITH (security_barrier)", "", 1)},
		{"filter on the wrong column", strings.Replace(created, filter, "\nWHERE b.id = 1", 1)},
		{"OR true", strings.Replace(created, filter, filter+" OR true", 1)},
		{"barrier dropped", strings.Replace(created, " WITH (security_barrier)", "", 1)},
		{"extra raw column", strings.Replace(created, "\nFROM ", ",\n       b.body AS raw_body\nFROM ", 1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, q := range []string{`DROP VIEW "mpa_support"."tickets"`, c.sql, `GRANT SELECT ON "mpa_support"."tickets" TO mpa_support`} {
				if _, err := conn.Exec(ctx, q); err != nil {
					t.Fatalf("%v\n%s", err, q)
				}
			}
			check(t, "mpa_support", true, false, "view mpa_support.tickets")
			// apply again restores the policy's view.
			again, err := PlanPostgres(ctx, conn, p, "app", cls, key, passwords, internal)
			if err != nil {
				t.Fatal(err)
			}
			if err := RunPostgres(ctx, conn, again); err != nil {
				t.Fatal(err)
			}
			check(t, "mpa_support", true, true)
		})
	}

	t.Run("refuses a role it did not create", func(t *testing.T) {
		if _, err := conn.Exec(ctx, "CREATE ROLE mpa_squatter"); err != nil {
			t.Fatal(err)
		}
		q := testPolicy()
		q.Identities["mpa_squatter"] = policy.Identity{Sources: []string{"app"}, Tables: []string{"mpa_app.users"}, Login: "none", Audit: "none"}
		_, err := PlanPostgres(ctx, conn, q, "app", cls, key, passwords, internal)
		if err == nil || !strings.Contains(err.Error(), "role mpa_squatter already exists and maskplan did not create it") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("drops an identity the policy no longer has", func(t *testing.T) {
		q := testPolicy()
		delete(q.Identities, "mpa_support")
		plan, err := PlanPostgres(ctx, conn, q, "app", cls, key, passwords, internal)
		if err != nil {
			t.Fatal(err)
		}
		if err := RunPostgres(ctx, conn, plan); err != nil {
			t.Fatal(err)
		}
		var role, schema bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mpa_support'), EXISTS (SELECT FROM pg_namespace WHERE nspname = 'mpa_support')").Scan(&role, &schema); err != nil {
			t.Fatal(err)
		}
		if role || schema {
			t.Errorf("mpa_support role %v, schema %v; want both dropped", role, schema)
		}
		check(t, "mpa_agent", true, true)
	})
}
