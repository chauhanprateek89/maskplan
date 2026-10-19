package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// The secrets-never-printed check, in one place. A run drives every command
// end to end, error paths included, and keeps everything maskplan writes:
// stdout, stderr, and the files it creates. Nothing of it may contain the
// key, any 8-byte window of the key-derived part of the pads (hex or
// base64), a password, a SCRAM verifier, or a value sampled from the data.
// Leaks of this kind were found twice in one day in paths without a
// fixture; this covers the paths fixtures do not think of.

const (
	secretKey      = "secrets-test-key-0123456789abcdef"
	secretPassword = "secrets-test-pw-Zq81"
)

// secretValues are the rows the run reads; none may be printed.
var secretValues = []string{"Siobhan.Kelly@example.ie", "siobhan.kelly@example.ie", "Siobhan Kelly", "+353 87 555 0142", "Oisin Byrne", "oisin.b@example.ie"}

type transcript struct {
	t   *testing.T
	out bytes.Buffer
}

// run runs a command, keeps its output, and checks its exit status.
func (tr *transcript) run(want int, args ...string) {
	tr.t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	fmt.Fprintf(&tr.out, "$ maskplan %s\n%s%s", strings.Join(args, " "), out.String(), errOut.String())
	if code != want {
		tr.t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, out.String(), errOut.String())
	}
}

// file keeps a file maskplan wrote.
func (tr *transcript) file(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		tr.t.Fatal(err)
	}
	fmt.Fprintf(&tr.out, "# %s\n%s", path, data)
}

func (tr *transcript) check() {
	tr.t.Helper()
	text := tr.out.String()
	for _, s := range secretStrings() {
		if i := strings.Index(text, s); i >= 0 {
			lo, hi := max(0, i-200), min(len(text), i+len(s)+50)
			tr.t.Errorf("output contains a secret (%q):\n...%s...", s, text[lo:hi])
		}
	}
	if strings.Contains(text, "SCRAM-SHA-256$") {
		tr.t.Error("output contains a SCRAM verifier")
	}
	if tr.t.Failed() || testing.Verbose() {
		tr.t.Logf("%d bytes of output checked", len(text))
	}
}

func secretStrings() []string {
	out := []string{secretKey, secretPassword, hex.EncodeToString([]byte(secretKey))[:16]}
	out = append(out, secretValues...)
	ipad, opad := token.Pads([]byte(secretKey))
	for _, pad := range [][]byte{ipad, opad} {
		// Past the key's length the pads are constant filler (0x36, 0x5c),
		// which is not secret and could match by chance.
		derived := pad[:len(secretKey)]
		for i := 0; i+8 <= len(derived); i++ {
			w := derived[i : i+8]
			out = append(out, hex.EncodeToString(w), strings.ToUpper(hex.EncodeToString(w)))
		}
		out = append(out, base64.StdEncoding.EncodeToString(derived)[:12])
	}
	return out
}

// keyInView is a token expression with the pads written into the view as
// literals, in two quoting styles: a view a careless user might write.
func keyInView(t *testing.T, e sqlexpr.Engine, col string) string {
	ipad, opad := token.Pads([]byte(secretKey))
	var pads sqlexpr.Pads
	if e == sqlexpr.Postgres {
		pads = sqlexpr.Pads{IPad: fmt.Sprintf(`$k$\x%x$k$::bytea`, ipad), OPad: fmt.Sprintf(`'\x%x'::bytea`, opad)}
	} else {
		pads = sqlexpr.Pads{IPad: fmt.Sprintf("0x%x", ipad), OPad: fmt.Sprintf("X'%x'", opad)}
	}
	x, err := sqlexpr.Token(e, sqlexpr.Column{Expr: col, Label: classify.Email, Normalizer: token.Email}, pads)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func writePolicy(t *testing.T, dir, engine, identity, table string) string {
	t.Helper()
	path := filepath.Join(dir, "maskplan.yaml")
	text := fmt.Sprintf(`version: 1
key: env:MPS_KEY
sources:
  app: { engine: %s, dsn: env:MPS_DSN }
identities:
  %s:
    sources: [app]
    tables: [%s]
    login: password
    password: env:MPS_PASSWORD
rules:
  - { label: user.contact.email, transform: token }
  - { label: user.name, transform: fake_name }
  - { label: user.contact.phone, transform: prefix, params: { keep: 4 } }
`, engine, identity, table)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNoSecretsPostgres(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	drop := func() {
		for _, q := range []string{"DROP SCHEMA IF EXISTS mps_app, mps_reader, mps_internal CASCADE", "DROP ROLE IF EXISTS mps_reader", "DROP ROLE IF EXISTS mps_peek"} {
			conn.Exec(ctx, q)
		}
	}
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE SCHEMA mps_app",
		"CREATE TABLE mps_app.customers (id int PRIMARY KEY, email text, full_name text, phone text)",
		fmt.Sprintf("INSERT INTO mps_app.customers VALUES (1, '%s', '%s', '%s'), (2, '%s', '%s', NULL)",
			secretValues[0], secretValues[2], secretValues[3], secretValues[5], secretValues[4]),
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	// After apply: a careless view with the key written into it.
	peek := func() {
		for _, q := range []string{"CREATE ROLE mps_peek",
			"CREATE VIEW mps_app.peek AS SELECT " + keyInView(t, sqlexpr.Postgres, "c.email") + " AS email, c.full_name FROM mps_app.customers c",
			"GRANT USAGE ON SCHEMA mps_app TO mps_peek", "GRANT SELECT ON mps_app.peek TO mps_peek"} {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatalf("%v\n%s", err, q)
			}
		}
	}
	runSecretTranscript(t, dsn, "postgres", "mps_reader", "mps_peek", peek)
}

func TestNoSecretsMySQL(t *testing.T) {
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
		for _, q := range []string{"DROP DATABASE IF EXISTS mps_app", "DROP DATABASE IF EXISTS mps_reader", "DROP DATABASE IF EXISTS mps_internal",
			"DROP USER IF EXISTS mps_reader@'%', mps_peek@'%'"} {
			db.ExecContext(ctx, q)
		}
	}
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE DATABASE mps_app",
		"CREATE TABLE mps_app.customers (id int PRIMARY KEY, email varchar(100), full_name varchar(100), phone varchar(30))",
		fmt.Sprintf("INSERT INTO mps_app.customers VALUES (1, '%s', '%s', '%s'), (2, '%s', '%s', NULL), (3, 'x@example.ie', 'X', NULL)",
			secretValues[0], secretValues[2], secretValues[3], secretValues[5], secretValues[4]),
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	peek := func() {
		for _, q := range []string{"CREATE USER mps_peek@'%' IDENTIFIED BY 'peek-pw-1'",
			"CREATE VIEW mps_app.peek AS SELECT " + keyInView(t, sqlexpr.MySQL, "c.email") + " AS email, c.full_name FROM mps_app.customers c",
			"GRANT SELECT ON mps_app.peek TO mps_peek@'%'"} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatalf("%v\n%s", err, q)
			}
		}
	}
	runSecretTranscript(t, dsn, "mysql", "mps_reader", "mps_peek@%", peek)
}

// runSecretTranscript drives every command over the mps_app fixture.
func runSecretTranscript(t *testing.T, dsn, engine, identity, peek string, addPeek func()) {
	dir := t.TempDir()
	cls := filepath.Join(dir, "classification.yaml")
	t.Setenv("MPS_DSN", dsn)
	t.Setenv("MPS_KEY", secretKey)
	t.Setenv("MPS_PASSWORD", secretPassword)
	tr := &transcript{t: t}
	policy := writePolicy(t, dir, engine, identity, "mps_app.customers")
	internal := []string{"--internal-schema", "mps_internal"}

	tr.run(0, "scan", "--dsn", dsn, "--schema", "mps_app", "--out", cls)
	tr.file(cls)
	tr.run(0, "init", "--classification", cls, "--identity", "mps_draft", "--out", filepath.Join(dir, "draft.yaml"))
	tr.file(filepath.Join(dir, "draft.yaml"))
	tr.run(0, append([]string{"plan", "--policy", policy}, internal...)...)
	tr.run(0, append([]string{"apply", "--policy", policy}, internal...)...)
	tr.run(0, append([]string{"apply", "--policy", policy, "--yes"}, internal...)...)
	tr.run(0, append([]string{"apply", "--policy", policy, "--yes"}, internal...)...) // idempotent second run
	report := func(want int, role string, extra ...string) {
		args := append([]string{"report", "--dsn", dsn, "--role", role, "--classification", cls, "--schema", "mps_app," + identity}, internal...)
		tr.run(want, append(args, extra...)...)
	}
	r := identity
	if engine == "mysql" {
		r += "@%"
	}
	report(0, r, "--policy", policy)
	report(0, r, "--policy", policy, "--json", "--show-expressions")
	addPeek()
	// The careless view: KEY findings, with and without expressions.
	report(1, peek)
	report(1, peek, "--show-expressions")
	report(1, peek, "--show-expressions", "--json")
	// Error paths: a missing environment variable, an unknown role, a
	// policy whose apply fails part way through.
	t.Setenv("MPS_PASSWORD", "")
	tr.run(2, append([]string{"apply", "--policy", policy, "--yes"}, internal...)...)
	t.Setenv("MPS_PASSWORD", secretPassword)
	report(2, "mps_no_such_role")
	broken := writePolicy(t, t.TempDir(), engine, identity, "mps_app.no_such_table")
	tr.run(2, append([]string{"apply", "--policy", broken, "--yes"}, internal...)...)
	tr.run(0, append([]string{"destroy", "--policy", policy}, internal...)...)
	tr.run(0, append([]string{"destroy", "--policy", policy, "--yes"}, internal...)...)
	tr.check()
}
