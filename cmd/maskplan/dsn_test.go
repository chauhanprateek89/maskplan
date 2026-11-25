package main

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A DSN's password must never reach stdout or stderr, whichever way the
// DSN arrives (--dsn, MASKPLAN_DSN, a policy's env: or literal dsn) and
// whichever way it fails: it does not parse, the driver rejects it, or the
// server cannot be reached or refuses it. Every case below fails; the
// check is that the failure is reported without the password.

const (
	dsnPassword = "dsn-test-pw-7c41"
	// dsnSpecial needs escaping in a URL, so it can leak as written,
	// decoded or encoded.
	dsnSpecial        = "p@ss:w/rd%7c41"
	dsnSpecialEscaped = "p%40ss%3Aw%2Frd%257c41"
)

// dsnLeaks lists the forms of the test passwords that must not be printed.
var dsnLeaks = []string{dsnPassword, dsnSpecial, dsnSpecialEscaped, "w/rd%7c41", "rd%257c41"}

func dsnCases(live string) map[string]string {
	pw := dsnPassword
	cases := map[string]string{
		"mysql url, bad port":           "mysql://bob:" + pw + "@db.example:33x06/app",
		"mysql url, bad ipv6 host":      "mysql://bob:" + pw + "@[::1/app",
		"mysql url, unreachable":        "mysql://bob:" + pw + "@127.0.0.1:1/app?timeout=2s",
		"mysql url, escaped password":   "mysql://bob:" + dsnSpecialEscaped + "@127.0.0.1:1/app?timeout=2s",
		"mysql driver, unreachable":     "bob:" + pw + "@tcp(127.0.0.1:1)/app?timeout=2s",
		"mysql driver, unclosed brace":  "bob:" + pw + "@tcp(127.0.0.1:1/app",
		"mysql driver, bad param":       "bob:" + pw + "@tcp(127.0.0.1:1)/app?tls=bogus",
		"mysql driver, bad bool":        "bob:" + pw + "@tcp(127.0.0.1:1)/app?parseTime=maybe",
		"mysql driver, unescaped param": "bob:" + pw + "@tcp(127.0.0.1:1)/app?loc=Europe/Dublin",
		"postgres url, unreachable":     "postgres://bob:" + pw + "@127.0.0.1:1/app?connect_timeout=2",
		"postgresql url, unreachable":   "postgresql://bob:" + pw + "@127.0.0.1:1/app?connect_timeout=2",
		"postgres url, bad port":        "postgres://bob:" + pw + "@db.example:99999/app",
		"postgres url, bad sslmode":     "postgres://bob:" + pw + "@127.0.0.1:1/app?sslmode=bogus",
		"postgres url, bad timeout":     "postgres://bob:" + pw + "@127.0.0.1:1/app?connect_timeout=soon",
		"postgres url, query password":  "postgres://127.0.0.1:1/app?user=bob&password=" + pw + "&connect_timeout=2",
		"postgres url, escaped":         "postgres://bob:" + dsnSpecialEscaped + "@127.0.0.1:1/app?connect_timeout=2",
		"postgres url, raw special":     "postgres://bob:" + dsnSpecial + "@127.0.0.1:1/app?connect_timeout=2",
		"postgres key=value":            "host=127.0.0.1 port=1 user=bob password=" + pw + " dbname=app connect_timeout=2",
		"postgres key=value, quoted":    "host=127.0.0.1 port=1 user=bob password='" + pw + " x' dbname=app connect_timeout=2",
		"postgres key=value, bad port":  "host=127.0.0.1 port=nine user=bob password=" + pw + " dbname=app",
	}
	if live != "" {
		// A server that is up and refuses the password.
		if u, err := url.Parse(live); err == nil && u.User != nil {
			u.User = url.UserPassword(u.User.Username(), pw)
			cases["postgres, wrong password"] = u.String()
		}
	}
	return cases
}

func TestDSNPasswordNeverPrinted(t *testing.T) {
	dir := t.TempDir()
	cls := filepath.Join(dir, "classification.yaml")
	if err := os.WriteFile(cls, []byte("version: 1\nsource: {engine: postgres, database: app}\ncolumns: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MASKPLAN_KEY", "dsn-test-key")
	var all bytes.Buffer
	check := func(t *testing.T, args ...string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		text := out.String() + errOut.String()
		all.WriteString(text)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, code, text)
		}
		for _, leak := range dsnLeaks {
			if strings.Contains(text, leak) {
				t.Errorf("%v printed the password (%q):\n%s", args, leak, text)
			}
		}
	}
	for name, dsn := range dsnCases(os.Getenv("MASKPLAN_TEST_POSTGRES_DSN")) {
		t.Run(name, func(t *testing.T) {
			engine := "postgres"
			if strings.HasPrefix(dsn, "mysql://") || strings.Contains(dsn, "@tcp(") {
				engine = "mysql"
			}
			check(t, "scan", "--dsn", dsn, "--out", filepath.Join(dir, "out.yaml"))
			check(t, "report", "--dsn", dsn, "--role", "agent", "--classification", cls)
			t.Setenv("MASKPLAN_DSN", dsn)
			check(t, "scan", "--out", filepath.Join(dir, "out.yaml"))
			check(t, "report", "--role", "agent", "--classification", cls)
			t.Setenv("MASKPLAN_DSN", "")
			for _, ref := range []string{"env:APP_DSN", dsn} {
				t.Setenv("APP_DSN", dsn)
				pol := filepath.Join(dir, "maskplan.yaml")
				body := "version: 1\nkey: env:MASKPLAN_KEY\nsources:\n  app:\n    engine: " + engine + "\n    dsn: " + quoteYAML(ref) +
					"\n    classification: classification.yaml\nidentities:\n  agent:\n    sources: [app]\n    tables: [public.t]\n"
				if err := os.WriteFile(pol, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				check(t, "plan", "--policy", pol)
				check(t, "apply", "--policy", pol)
			}
		})
	}
	// The redaction keeps what makes an error useful.
	if !strings.Contains(all.String(), "mysql://bob:***@db.example:33x06/app") {
		t.Errorf("the unparsable mysql URL was not shown redacted:\n%s", all.String())
	}
}

func quoteYAML(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
