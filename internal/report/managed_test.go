package report

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/scan"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// TestManagedSimPostgres runs the report on a simulated managed service:
// pgaudit, pg_stat_statements and PostGIS installed by a superuser, a
// stand-in vendor extension with a SECURITY DEFINER function executable by
// PUBLIC (testdata/managed), and roles shaped like RDS's: rds_superuser
// (with pg_monitor), rds_iam, and a master user that is a member of
// rds_superuser and owns the application. It is a simulation: real RDS,
// Cloud SQL and Azure catalogs have not been tested.
//
// MASKPLAN_TEST_MANAGED_DSN must name a superuser connection to a database
// used only for this test, on a server built from testdata/managed.
func TestManagedSimPostgres(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_MANAGED_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_MANAGED_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })

	// RDS's own roles are created only if missing, and only those are dropped.
	var created []string
	for _, r := range []string{"rds_superuser", "rds_iam", "rds_password", "rds_replication"} {
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", r).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			exec(t, conn, "CREATE ROLE "+r+" NOLOGIN")
			created = append(created, r)
		}
	}
	cleanup := func() {
		for _, q := range []string{"DROP SCHEMA IF EXISTS mpm_app, mpm_masked, mpm_internal CASCADE",
			"DROP OWNED BY mpm_agent", "DROP ROLE IF EXISTS mpm_agent", "DROP OWNED BY mpm_admin", "DROP ROLE IF EXISTS mpm_admin"} {
			conn.Exec(ctx, q)
		}
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		for _, r := range created {
			conn.Exec(ctx, "DROP ROLE IF EXISTS "+r)
		}
	})

	ipad, opad := token.Pads(testKey)
	_, pads, _ := sqlexpr.KeySource(sqlexpr.Postgres, "mpm_internal.key_material", "k")
	tok := func(expr, label string, n token.Normalizer) string {
		s, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{Expr: expr, Label: label, Normalizer: n}, pads)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	exec(t, conn,
		"CREATE EXTENSION IF NOT EXISTS pg_stat_statements",
		"CREATE EXTENSION IF NOT EXISTS pgaudit",
		"CREATE EXTENSION IF NOT EXISTS postgis",
		"CREATE EXTENSION IF NOT EXISTS maskplan_sim_managed",
		"GRANT pg_monitor, pg_signal_backend, rds_password, rds_replication TO rds_superuser",
		// The master user: not a superuser, but it owns the application.
		"CREATE ROLE mpm_admin LOGIN CREATEROLE CREATEDB",
		"GRANT rds_superuser TO mpm_admin WITH ADMIN OPTION",
		// The agent logs in with an IAM token, and its reads are audited.
		"CREATE ROLE mpm_agent LOGIN CONNECTION LIMIT 5",
		"GRANT rds_iam TO mpm_agent",
		"ALTER ROLE mpm_agent SET pgaudit.log = 'read'",
		"ALTER ROLE mpm_agent SET statement_timeout = '30s'",
		"CREATE SCHEMA mpm_app AUTHORIZATION mpm_admin",
		"CREATE SCHEMA mpm_masked AUTHORIZATION mpm_admin",
		"CREATE SCHEMA mpm_internal AUTHORIZATION mpm_admin",
		"SET ROLE mpm_admin",
		"CREATE TABLE mpm_app.customers (id int PRIMARY KEY, email text, phone text, home geography(Point))",
		"INSERT INTO mpm_app.customers SELECT g, 'c' || g || '@example.ie', '+353 87 555 ' || lpad(g::text, 4, '0'), NULL FROM generate_series(1, 200) g",
		"CREATE TABLE mpm_internal.key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad bytea NOT NULL, opad bytea NOT NULL)",
	)
	if _, err := conn.Exec(ctx, "INSERT INTO mpm_internal.key_material VALUES (1, $1, $2)", ipad, opad); err != nil {
		t.Fatal(err)
	}
	exec(t, conn,
		fmt.Sprintf("CREATE VIEW mpm_masked.customers AS SELECT c.id, %s AS email, %s AS phone FROM mpm_app.customers c",
			tok("c.email", classify.Email, token.Email), tok("c.phone", classify.Phone, token.Phone)),
		"GRANT USAGE ON SCHEMA mpm_masked TO mpm_agent",
		"GRANT SELECT ON mpm_masked.customers TO mpm_agent",
		"RESET ROLE",
		"ANALYZE mpm_app.customers",
	)

	// As in real use: scan the whole database, then report on every schema.
	cls, err := scan.Postgres(ctx, conn, scan.Options{InternalSchema: "mpm_internal"})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{InternalSchema: "mpm_internal"}

	agent, err := Postgres(ctx, conn, "mpm_agent", cls, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + dump(agent))
	if agent.Failed() {
		t.Errorf("the agent reads only a masked view, but the report fails it")
	}
	for _, want := range []expect{
		{Masked, "mpm_masked.customers.email", nil},
		{Masked, "mpm_masked.customers.phone", nil},
		{Warn, "function public.sim_managed_table_count()", []string{"from extension maskplan_sim_managed"}},
	} {
		found := false
		for _, f := range agent.Findings {
			found = found || want.matches(f)
		}
		if !found {
			t.Errorf("agent: missing %s %s", want.status, want.object)
		}
	}
	if s := agent.Settings; s.Login != "IAM token (rds_iam)" || !strings.Contains(s.Audit, "pgaudit.log = read") ||
		s.ConnectionLimit != "5 (enforced)" || !strings.HasPrefix(s.StatementTimeout, "30s") {
		t.Errorf("agent settings: %+v", s)
	}

	admin, err := Postgres(ctx, conn, "mpm_admin", cls, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []expect{
		{Unknown, "role", []string{"member of rds_superuser"}},
		{Raw, "mpm_app.customers.email", []string{"owner mpm_admin"}},
		{Key, "mpm_internal.key_material", nil},
		{Warn, "role", []string{"pg_monitor"}},
	} {
		found := false
		for _, f := range admin.Findings {
			found = found || want.matches(f)
		}
		if !found {
			t.Errorf("master user: missing %s %s\n%s", want.status, want.object, dump(admin))
		}
	}
}
