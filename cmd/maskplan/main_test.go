package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"frobnicate"},
		{"report", "--dsn", "postgres://x@localhost/x"},
		{"report", "--role", "r", "--classification", t.TempDir() + "/missing.yaml"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"report", "--role", "r", "--classification", writeEmptyClassification(t), "--dsn", "mysql://u:p@db.invalid/x"}, &out, &errOut); code != 2 {
		t.Errorf("report on an unreachable mysql: exit %d, %s", code, errOut.String())
	}
	for in, want := range map[string]string{
		"mysql://u:p@db.example:3307/app": "u:p@tcp(db.example:3307)/app",
		"mysql://u:p@db.example/app":      "u:p@tcp(db.example:3306)/app",
		"u:p@tcp(h:3306)/app":             "u:p@tcp(h:3306)/app",
	} {
		got, isMySQL, err := resolveDSN(in)
		if err != nil || !isMySQL || !strings.HasPrefix(got, want) {
			t.Errorf("resolveDSN(%q) = %q, %v, %v; want prefix %q", in, got, isMySQL, err, want)
		}
	}
	if _, isMySQL, _ := resolveDSN("postgres://u@h/db"); isMySQL {
		t.Error("postgres DSN taken for MySQL")
	}
}

func writeEmptyClassification(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/c.yaml"
	if err := classification.Save(path, &classification.File{Version: classification.Version}); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScanReportPostgres runs the two commands end to end.
func TestScanReportPostgres(t *testing.T) {
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
	cleanup := []string{"DROP SCHEMA IF EXISTS mpc_cli CASCADE", "DROP ROLE IF EXISTS mpc_agent", "DROP ROLE IF EXISTS mpc_clean"}
	drop := func() {
		for _, q := range cleanup {
			conn.Exec(ctx, q)
		}
	}
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE ROLE mpc_agent", "CREATE ROLE mpc_clean",
		"CREATE SCHEMA mpc_cli",
		"CREATE TABLE mpc_cli.customers (id int, email text, handle text)",
		"INSERT INTO mpc_cli.customers SELECT g, 'u' || g || '@example.com', 'n' || g FROM generate_series(1, 20) g",
		"CREATE TABLE mpc_cli.orders (id int, total numeric)",
		"GRANT USAGE ON SCHEMA mpc_cli TO mpc_agent, mpc_clean",
		"GRANT SELECT ON mpc_cli.customers TO mpc_agent",
		"GRANT SELECT ON mpc_cli.orders TO mpc_clean",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	cls := t.TempDir() + "/classification.yaml"
	cmd := func(want int, args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(append(args, "--dsn", dsn, "--schema", "mpc_cli"), &out, &errOut); code != want {
			t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, out.String(), errOut.String())
		}
		return out.String()
	}

	out := cmd(0, "scan", "--out", cls)
	if !strings.Contains(out, "5 columns in 2 tables: 1 labeled as personal data") {
		t.Errorf("scan summary: %s", out)
	}

	// A reviewer labels handle by hand; a second scan keeps it.
	f, err := classification.Load(cls)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range f.Columns {
		if c.Column == "handle" {
			f.Columns[i].Label, f.Columns[i].Reviewed = "user.name", true
		}
	}
	if err := classification.Save(cls, f); err != nil {
		t.Fatal(err)
	}
	cmd(0, "scan", "--out", cls)
	if f, err = classification.Load(cls); err != nil {
		t.Fatal(err)
	}
	if c := f.Index()[classification.Key{Schema: "mpc_cli", Table: "customers", Column: "handle"}]; c.Label != "user.name" || !c.Reviewed {
		t.Errorf("rescan overwrote a reviewed entry: %+v", c)
	}

	out = cmd(1, "report", "--role", "mpc_agent", "--classification", cls)
	for _, want := range []string{"RAW       mpc_cli.customers.email", "mpc_cli.customers.handle", "FAIL"} {
		if !strings.Contains(out, want) {
			t.Errorf("report for mpc_agent lacks %q:\n%s", want, out)
		}
	}
	out = cmd(0, "report", "--role", "mpc_clean", "--classification", cls)
	if !strings.Contains(out, "PASS") {
		t.Errorf("report for mpc_clean:\n%s", out)
	}
	out = cmd(1, "report", "--role", "mpc_agent", "--classification", cls, "--json")
	var j struct {
		Failed bool           `json:"failed"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil {
		t.Fatal(err)
	}
	if !j.Failed || j.Counts["RAW"] != 2 {
		t.Errorf("json: %+v", j)
	}
	cmd(2, "report", "--role", "mpc_no_such_role", "--classification", cls)
}

// TestScanReportMySQL runs scan and report end to end against MySQL.
func TestScanReportMySQL(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_MYSQL_DSN not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	drop := func() {
		for _, q := range []string{"DROP DATABASE IF EXISTS mpc_cli", "DROP USER IF EXISTS mpc_agent@'%'", "DROP USER IF EXISTS mpc_clean@'%'"} {
			db.ExecContext(ctx, q)
		}
	}
	drop()
	defer drop()
	for _, q := range []string{"CREATE DATABASE mpc_cli",
		"CREATE TABLE mpc_cli.customers (id int PRIMARY KEY, email varchar(100))",
		"INSERT INTO mpc_cli.customers VALUES (1, 'a@example.com'), (2, 'b@example.com')",
		"CREATE TABLE mpc_cli.orders (id int PRIMARY KEY, total decimal(10,2))",
		"CREATE USER mpc_agent@'%' IDENTIFIED BY 'x'", "CREATE USER mpc_clean@'%' IDENTIFIED BY 'x'",
		"GRANT SELECT ON mpc_cli.customers TO mpc_agent@'%'", "GRANT SELECT ON mpc_cli.orders TO mpc_clean@'%'"} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	cls := t.TempDir() + "/classification.yaml"
	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "--dsn", dsn, "--schema", "mpc_cli", "--out", cls}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	f, err := classification.Load(cls)
	if err != nil {
		t.Fatal(err)
	}
	if f.Source.Engine != "mysql" || f.Index()[classification.Key{Schema: "mpc_cli", Table: "customers", Column: "email"}].Label != "user.contact.email" {
		t.Errorf("scan result: %+v", f)
	}
	for account, want := range map[string]int{"mpc_agent@%": 1, "mpc_clean": 0} {
		out.Reset()
		errOut.Reset()
		code := run([]string{"report", "--dsn", dsn, "--schema", "mpc_cli", "--classification", cls, "--role", account}, &out, &errOut)
		if code != want {
			t.Errorf("report %s: exit %d, want %d\n%s%s", account, code, want, out.String(), errOut.String())
		}
		if want == 0 && !strings.Contains(out.String(), "PASS") {
			t.Errorf("clean account report:\n%s", out.String())
		}
	}
}

// TestApplyCLIPostgres runs scan, plan, apply and destroy end to end.
func TestApplyCLIPostgres(t *testing.T) {
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
		for _, q := range []string{"DROP SCHEMA IF EXISTS mpc_app, mpc_reader, mpc_internal CASCADE", "DROP ROLE IF EXISTS mpc_reader"} {
			conn.Exec(ctx, q)
		}
	}
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE SCHEMA mpc_app",
		"CREATE TABLE mpc_app.customers (id int PRIMARY KEY, email text, full_name text, signup date)",
		"INSERT INTO mpc_app.customers SELECT g, 'u' || g || '@example.com', 'Name ' || g, date '2024-01-01' + g FROM generate_series(1, 20) g",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	dir := t.TempDir()
	t.Setenv("MPC_DSN", dsn)
	t.Setenv("MPC_KEY", "cli-test-key-0123456789abcdef!!!")
	t.Setenv("MPC_READER_PASSWORD", "cli-reader-pw")
	pol := dir + "/maskplan.yaml"
	if err := os.WriteFile(pol, []byte(`version: 1
key: env:MPC_KEY
sources:
  app: { engine: postgres, dsn: env:MPC_DSN }
identities:
  mpc_reader:
    sources: [app]
    tables: [mpc_app.customers]
    login: password
    password: env:MPC_READER_PASSWORD
rules:
  - { label: user.contact.email, transform: token }
  - { label: user.name, transform: fake_name }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := func(want int, args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != want {
			t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, out.String(), errOut.String())
		}
		return out.String()
	}
	cmd(0, "scan", "--dsn", dsn, "--schema", "mpc_app", "--out", dir+"/classification.yaml")
	exists := func() bool {
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mpc_reader')").Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	out := cmd(0, "plan", "--policy", pol, "--internal-schema", "mpc_internal")
	for _, want := range []string{`CREATE VIEW "mpc_reader"."customers"`, `PASSWORD '…'`, "with 2 parameters, not shown"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"cli-test-key", "cli-reader-pw", "SCRAM-SHA-256$"} {
		if strings.Contains(out, secret) {
			t.Errorf("plan shows %q", secret)
		}
	}
	if out := cmd(0, "apply", "--policy", pol, "--internal-schema", "mpc_internal"); !strings.Contains(out, "nothing changed") || exists() {
		t.Errorf("apply without --yes changed something:\n%s", out)
	}
	for i := 0; i < 2; i++ { // the second apply changes nothing and passes again
		out = cmd(0, "apply", "--policy", pol, "--internal-schema", "mpc_internal", "--yes")
		for _, want := range []string{"source app: apply done", "role: mpc_reader", "maskplan token of mpc_app.customers.email", "PASS"} {
			if !strings.Contains(out, want) {
				t.Errorf("apply %d lacks %q:\n%s", i+1, want, out)
			}
		}
	}
	cmd(0, "report", "--dsn", dsn, "--role", "mpc_reader", "--classification", dir+"/classification.yaml",
		"--policy", pol, "--internal-schema", "mpc_internal")
	if _, err := conn.Exec(ctx, `CREATE OR REPLACE VIEW mpc_reader.customers AS SELECT id, email, full_name, signup FROM mpc_app.customers`); err != nil {
		t.Fatal(err)
	}
	cmd(1, "report", "--dsn", dsn, "--role", "mpc_reader", "--classification", dir+"/classification.yaml",
		"--policy", pol, "--internal-schema", "mpc_internal")

	cmd(0, "destroy", "--policy", pol, "--internal-schema", "mpc_internal", "--yes")
	var internal bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname IN ('mpc_internal', 'mpc_reader'))").Scan(&internal); err != nil {
		t.Fatal(err)
	}
	if exists() || internal {
		t.Errorf("destroy left the role (%v) or a schema (%v)", exists(), internal)
	}
}

// TestApplyCLIMySQL runs scan, plan, apply and destroy end to end on MySQL.
func TestApplyCLIMySQL(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_MYSQL_DSN not set")
	}
	ctx := context.Background()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	drop := func() {
		for _, q := range []string{"DROP DATABASE IF EXISTS mpc_app", "DROP DATABASE IF EXISTS mpc_reader", "DROP DATABASE IF EXISTS mpc_internal", "DROP USER IF EXISTS mpc_reader@'%'"} {
			db.ExecContext(ctx, q)
		}
	}
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE DATABASE mpc_app",
		"CREATE TABLE mpc_app.customers (id int PRIMARY KEY, email varchar(100), full_name varchar(100), signup date)",
		"INSERT INTO mpc_app.customers VALUES (1, 'u1@example.com', 'Name One', '2024-01-02'), (2, 'u2@example.com', 'Name Two', '2024-01-03'), (3, 'u3@example.com', 'Name Three', '2024-01-04')",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	dir := t.TempDir()
	t.Setenv("MPC_DSN", dsn)
	t.Setenv("MPC_KEY", "cli-test-key-0123456789abcdef!!!")
	t.Setenv("MPC_READER_PASSWORD", "cli-reader-pw")
	pol := dir + "/maskplan.yaml"
	if err := os.WriteFile(pol, []byte(`version: 1
key: env:MPC_KEY
sources:
  app: { engine: mysql, dsn: env:MPC_DSN }
identities:
  mpc_reader:
    sources: [app]
    tables: [mpc_app.customers]
    login: password
    password: env:MPC_READER_PASSWORD
rules:
  - { label: user.contact.email, transform: token }
  - { label: user.name, transform: fake_name }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := func(want int, args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != want {
			t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, out.String(), errOut.String())
		}
		return out.String()
	}
	cls := dir + "/classification.yaml"
	cmd(0, "scan", "--dsn", dsn, "--schema", "mpc_app", "--out", cls)
	out := cmd(0, "plan", "--policy", pol, "--internal-schema", "mpc_internal")
	for _, want := range []string{"CREATE OR REPLACE SQL SECURITY DEFINER VIEW `mpc_reader`.`customers`", "IDENTIFIED BY '…'"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cli-reader-pw") || strings.Contains(out, "cli-test-key") {
		t.Errorf("plan shows a secret:\n%s", out)
	}
	for i := 0; i < 2; i++ {
		out = cmd(0, "apply", "--policy", pol, "--internal-schema", "mpc_internal", "--yes")
		for _, want := range []string{"source app: apply done", "'mpc_reader'@'%'", "maskplan token of mpc_app.customers.email", "PASS"} {
			if !strings.Contains(out, want) {
				t.Errorf("apply %d lacks %q:\n%s", i+1, want, out)
			}
		}
	}
	report := []string{"report", "--dsn", dsn, "--role", "mpc_reader@%", "--classification", cls, "--policy", pol, "--internal-schema", "mpc_internal"}
	cmd(0, report...)
	if _, err := db.ExecContext(ctx, "CREATE OR REPLACE VIEW mpc_reader.customers AS SELECT id, email, full_name, signup FROM mpc_app.customers"); err != nil {
		t.Fatal(err)
	}
	cmd(1, report...)
	cmd(0, "destroy", "--policy", pol, "--internal-schema", "mpc_internal", "--yes")
	var left int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM mysql.user WHERE User = 'mpc_reader')
		+ (SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('mpc_reader', 'mpc_internal'))`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("destroy left %d accounts or databases", left)
	}
}
