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
	if code := run([]string{"report", "--role", "r", "--classification", writeEmptyClassification(t), "--dsn", "mysql://u:p@db.invalid/x"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "does not support MySQL") {
		t.Errorf("report on mysql: exit %d, %s", code, errOut.String())
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

// TestScanMySQL runs scan end to end against MySQL.
func TestScanMySQL(t *testing.T) {
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
	for _, q := range []string{"DROP DATABASE IF EXISTS mpc_cli", "CREATE DATABASE mpc_cli",
		"CREATE TABLE mpc_cli.customers (id int PRIMARY KEY, email varchar(100))",
		"INSERT INTO mpc_cli.customers VALUES (1, 'a@example.com'), (2, 'b@example.com')"} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	defer db.ExecContext(ctx, "DROP DATABASE IF EXISTS mpc_cli")
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
}
