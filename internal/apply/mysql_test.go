package apply

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/report"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

func testPolicyMySQL() *policy.Policy {
	p := testPolicy()
	p.Sources = map[string]policy.Source{"app": {Engine: "mysql", DSN: "env:X"}}
	support := p.Identities["mpa_support"]
	support.Rows = nil // not supported on MySQL
	p.Identities["mpa_support"] = support
	agent := p.Identities["mpa_agent"]
	agent.Limits.StatementTimeout = ""
	p.Identities["mpa_agent"] = agent
	return p
}

func TestApplyMySQL(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_MYSQL_DSN not set")
	}
	ctx := context.Background()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	exec := func(t *testing.T, qs ...string) {
		t.Helper()
		for _, q := range qs {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatalf("%v\n%s", err, q)
			}
		}
	}
	drop := func() {
		for _, q := range []string{"DROP DATABASE IF EXISTS mpa_app", "DROP DATABASE IF EXISTS mpa_agent", "DROP DATABASE IF EXISTS mpa_support",
			"DROP DATABASE IF EXISTS " + internal, "DROP USER IF EXISTS mpa_agent@'%', mpa_support@'%', mpa_squatter@'%'"} {
			db.ExecContext(ctx, q)
		}
	}
	drop()
	if os.Getenv("MPA_KEEP") == "" {
		t.Cleanup(drop)
	}
	exec(t, "CREATE DATABASE mpa_app",
		`CREATE TABLE mpa_app.users (id int PRIMARY KEY, email varchar(100), full_name varchar(100), birth_date date, postcode varchar(10),
			phone varchar(30), country char(2), password_hash varchar(100), notes text, nickname varchar(30))`,
		"INSERT INTO mpa_app.users VALUES (1, 'Alice@Example.com', 'Alice Byrne', '1990-06-15', 'D02 X285', '+353 1 234 5678', 'IE', 'x', 'call after 5', 'ali'), (2, 'bob@example.com', 'Bob Ryan', '1985-01-02', 'T12 Y7K2', '01 234 5679', 'IE', 'y', NULL, 'bob')",
		"CREATE TABLE mpa_app.tickets (id int PRIMARY KEY, tenant_id int, requester_email varchar(100), body text)",
		"INSERT INTO mpa_app.tickets VALUES (1, 1, 'alice@example.com', 'hello'), (2, 2, 'eve@example.com', 'other tenant')")

	p := testPolicyMySQL()
	cls := testClassification()
	passwords := map[string]string{"mpa_agent": "mpa-agent-pw"}
	plan, err := PlanMySQL(ctx, db, p, "app", cls, key, passwords, internal)
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
	if err := RunMySQL(ctx, db, plan); err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + printed.String())

	check := func(t *testing.T, identity string, withPolicy, pass bool, want ...string) {
		t.Helper()
		opts := report.Options{Schemas: []string{"mpa_app", identity}, InternalSchema: internal}
		if withPolicy {
			opts.Policy = p
		}
		r, err := report.MySQL(ctx, db, identity+"@%", cls, opts)
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
				"maskplan token of mpa_app.users.email", "maskplan fake_name of mpa_app.users.full_name",
				"maskplan generalize_year of mpa_app.users.birth_date", "maskplan prefix of mpa_app.users.postcode",
				"maskplan token of mpa_app.users.phone", "maskplan fake_email of mpa_app.tickets.requester_email",
				"login: password", "connection limit: 3")
			check(t, "mpa_support", withPolicy, true, "maskplan fake_email of mpa_app.tickets.requester_email", "account locked")
		}
	})

	t.Run("agent reads masked values", func(t *testing.T) {
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.User, cfg.Passwd, cfg.DBName = "mpa_agent", "mpa-agent-pw", "mpa_agent"
		agent, err := sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			t.Fatal(err)
		}
		defer agent.Close()
		rows, err := agent.QueryContext(ctx, "SELECT * FROM users ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		var got []map[string]*string
		for rows.Next() {
			vals := make([]*string, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			m := map[string]*string{}
			for i, c := range cols {
				m[c] = vals[i]
			}
			got = append(got, m)
		}
		rows.Close()
		if want := []string{"id", "email", "full_name", "birth_date", "postcode", "phone", "country", "notes"}; !slices.Equal(cols, want) {
			t.Errorf("columns %v, want %v", cols, want)
		}
		alice := got[0]
		raw := "Alice@Example.com"
		str := func(p *string) string {
			if p == nil {
				return "<nil>"
			}
			return *p
		}
		if str(alice["email"]) != *token.Token(key, classify.Email, token.Email, &raw) {
			t.Errorf("email %s is not the token the spec gives (the same as on Postgres)", str(alice["email"]))
		}
		if !slices.Contains(compile.Names(), str(alice["full_name"])) {
			t.Errorf("full_name %s is not a dictionary name", str(alice["full_name"]))
		}
		if str(alice["birth_date"]) != "1990-01-01" || str(alice["postcode"]) != "D02" || alice["notes"] != nil {
			t.Errorf("birth_date %s, postcode %s, notes %s", str(alice["birth_date"]), str(alice["postcode"]), str(alice["notes"]))
		}
		for _, q := range []string{"SELECT email FROM mpa_app.users", "SELECT ipad FROM " + internal + ".key_material", "SELECT name FROM " + internal + ".names"} {
			if _, err := agent.ExecContext(ctx, q); err == nil {
				t.Errorf("agent can run %s", q)
			}
		}
	})

	t.Run("policy check", func(t *testing.T) {
		// A raw column added, then a token replaced by the raw value.
		for _, def := range []string{
			"CREATE OR REPLACE VIEW mpa_support.tickets AS SELECT b.id, b.tenant_id, 'x' AS requester_email, NULL AS body, b.body AS raw_body FROM mpa_app.tickets b",
			"CREATE OR REPLACE VIEW mpa_support.tickets AS SELECT b.id, b.tenant_id, b.id AS requester_email, NULL AS body FROM mpa_app.tickets b",
			"CREATE OR REPLACE VIEW mpa_support.tickets AS SELECT b.id, b.tenant_id, NULL AS requester_email, NULL AS body FROM mpa_app.tickets b WHERE b.tenant_id = 1",
		} {
			exec(t, def)
			check(t, "mpa_support", true, false, "view mpa_support.tickets")
			again, err := PlanMySQL(ctx, db, p, "app", cls, key, passwords, internal)
			if err != nil {
				t.Fatal(err)
			}
			if err := RunMySQL(ctx, db, again); err != nil {
				t.Fatal(err)
			}
			check(t, "mpa_support", true, true)
		}
	})

	t.Run("refuses what it cannot do or did not create", func(t *testing.T) {
		exec(t, "CREATE USER mpa_squatter@'%'")
		q := testPolicyMySQL()
		q.Identities["mpa_squatter"] = policy.Identity{Sources: []string{"app"}, Tables: []string{"mpa_app.users"}, Login: "none", Audit: "none"}
		if _, err := PlanMySQL(ctx, db, q, "app", cls, key, passwords, internal); err == nil || !strings.Contains(err.Error(), "did not create it") {
			t.Errorf("squatter: err = %v", err)
		}
		if _, err := PlanMySQL(ctx, db, testPolicy(), "app", cls, key, passwords, internal); err == nil || !strings.Contains(err.Error(), "rows filters are not supported on MySQL") {
			t.Errorf("rows filter: err = %v", err)
		}
	})

	t.Run("drops an identity the policy no longer has", func(t *testing.T) {
		q := testPolicyMySQL()
		delete(q.Identities, "mpa_support")
		plan, err := PlanMySQL(ctx, db, q, "app", cls, key, passwords, internal)
		if err != nil {
			t.Fatal(err)
		}
		if err := RunMySQL(ctx, db, plan); err != nil {
			t.Fatal(err)
		}
		var users, dbs, grants int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM mysql.user WHERE User = 'mpa_support'),
			(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'mpa_support'),
			(SELECT COUNT(*) FROM mysql.tables_priv WHERE User = 'mpa_support')`).Scan(&users, &dbs, &grants); err != nil {
			t.Fatal(err)
		}
		if users+dbs+grants != 0 {
			t.Errorf("mpa_support left: %d accounts, %d databases, %d grants", users, dbs, grants)
		}
		check(t, "mpa_agent", true, true)
	})
}
