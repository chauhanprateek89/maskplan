package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
)

const schema = "mps_scan"

func TestScanPostgres(t *testing.T) {
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
	drop := func() { conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE") }
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE SCHEMA " + schema,
		"CREATE DOMAIN " + schema + ".email_address AS text",
		`CREATE TABLE ` + schema + `.customers (id int, email text, contact ` + schema + `.email_address, "phoneNumber" varchar(32),
			iban text, ref text, ip inet, last_seen_from text, dob date, dob_text text, created date, payload jsonb, status text, notes text, amount_cents bigint)`,
		`INSERT INTO ` + schema + `.customers
			SELECT g, 'user' || g || '@example.com', 'c' || g || '@example.ie', '+353 1 555 ' || lpad(g::text, 4, '0'),
				CASE WHEN g % 2 = 0 THEN 'IE29AIBK93115212345678' ELSE 'GB82 WEST 1234 5698 7654 32' END,
				CASE WHEN g % 2 = 0 THEN '4111111111111111' ELSE '5500 0000 0000 0004' END,
				('10.0.0.' || g)::inet, '192.168.1.' || g, date '1980-01-01' + g, '1980-01-01', date '2026-01-01' + g,
				jsonb_build_object('k', g), 'active', NULL, 1000000 + g
			FROM generate_series(1, 50) g`,
		"CREATE TABLE " + schema + ".events (id int, at date) PARTITION BY RANGE (at)",
		"CREATE TABLE " + schema + ".events_2026 PARTITION OF " + schema + ".events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')",
		"CREATE MATERIALIZED VIEW " + schema + ".emails AS SELECT email FROM " + schema + ".customers WITH NO DATA",
		"CREATE TABLE " + schema + ".empty (email text)",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	f, err := Postgres(ctx, conn, Options{Schemas: []string{schema}})
	if err != nil {
		t.Fatal(err)
	}
	got := f.Index()
	want := map[string]string{
		"customers.id":             classify.None,
		"customers.email":          classify.Email,
		"customers.contact":        classify.Email, // values, through a domain
		"customers.phoneNumber":    classify.Phone,
		"customers.iban":           classify.IBAN,
		"customers.ref":            classify.CardNumber, // values only
		"customers.ip":             classify.IPAddress,
		"customers.last_seen_from": classify.IPAddress, // values only
		"customers.dob":            classify.BirthDate,
		"customers.dob_text":       classify.None, // a dob name on text is not trusted
		"customers.created":        classify.None,
		"customers.payload":        classify.FreeText,
		"customers.status":         classify.None,
		"customers.notes":          classify.FreeText,
		"customers.amount_cents":   classify.None, // numbers are not sampled for phone shapes
		"events.id":                classify.None,
		"events.at":                classify.None,
		"emails.email":             classify.Email,
		"empty.email":              classify.Email,
	}
	for k, label := range want {
		parts := strings.SplitN(k, ".", 2)
		c, ok := got[classification.Key{Schema: schema, Table: parts[0], Column: parts[1]}]
		if !ok {
			t.Errorf("%s not scanned", k)
			continue
		}
		if c.Label != label {
			t.Errorf("%s: label %s (%.2f, %v), want %s", k, c.Label, c.Confidence, c.Evidence, label)
		}
	}
	if len(f.Columns) != len(want) {
		var names []string
		for _, c := range f.Columns {
			names = append(names, c.Table+"."+c.Column)
		}
		t.Errorf("scanned %d columns, want %d (partitions are scanned through their root): %v", len(f.Columns), len(want), names)
	}
	mv := got[classification.Key{Schema: schema, Table: "emails", Column: "email"}]
	if !strings.Contains(fmt.Sprint(mv.Evidence), "not populated") {
		t.Errorf("unpopulated materialized view evidence: %v", mv.Evidence)
	}
	if c := got[classification.Key{Schema: schema, Table: "customers", Column: "email"}]; c.Confidence != 0.95 {
		t.Errorf("email confidence %.2f, want 0.95 (name and values agree)", c.Confidence)
	}

	// Sampled values must never reach the file.
	path := t.TempDir() + "/classification.yaml"
	if err := classification.Save(path, f); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"user1@example.com", "IE29AIBK", "4111", "10.0.0.1", "+353"} {
		if strings.Contains(string(data), v) {
			t.Errorf("classification file contains sampled value %q", v)
		}
	}
	back, err := classification.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Columns) != len(f.Columns) {
		t.Errorf("round trip: %d columns, want %d", len(back.Columns), len(f.Columns))
	}
}
