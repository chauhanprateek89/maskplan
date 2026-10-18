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
			iban text, ref text, ip inet, last_seen_from text, dob date, dob_text text, created date, payload jsonb, status text, notes text, amount_cents bigint,
			card_no bigint, mobile_number bigint, balance numeric, email_tok text)`,
		`INSERT INTO ` + schema + `.customers
			SELECT g, 'user' || g || '@example.com', 'c' || g || '@example.ie', '+353 1 555 ' || lpad(g::text, 4, '0'),
				CASE WHEN g % 2 = 0 THEN 'IE29AIBK93115212345678' ELSE 'GB82 WEST 1234 5698 7654 32' END,
				CASE WHEN g % 2 = 0 THEN '4111111111111111' ELSE '5500 0000 0000 0004' END,
				('10.0.0.' || g)::inet, '192.168.1.' || g, date '1980-01-01' + g, '1980-01-01', date '2026-01-01' + g,
				jsonb_build_object('k', g), 'active', NULL, 1000000 + g,
				CASE WHEN g % 2 = 0 THEN 4111111111111111 ELSE 5500000000000004 END, 353871230000 + g, 1000.5 + g,
				'tok_' || md5(g::text)
			FROM generate_series(1, 50) g`,
		"CREATE TABLE " + schema + ".events (id int, at date) PARTITION BY RANGE (at)",
		"CREATE TABLE " + schema + ".events_2026 PARTITION OF " + schema + ".events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')",
		"CREATE MATERIALIZED VIEW " + schema + ".emails AS SELECT email FROM " + schema + ".customers WITH NO DATA",
		"CREATE TABLE " + schema + ".empty (email text)",
		// The personal data comes after 300 bytes of namespace declarations.
		`CREATE TABLE ` + schema + `.contact_docs (id int, info xml)`,
		`INSERT INTO ` + schema + `.contact_docs SELECT g, ('<Info xmlns="` + strings.Repeat("x", 300) + `"><t:telephoneNumber>01 234 5678</t:telephoneNumber></Info>')::xml FROM generate_series(1, 5) g`,
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
		"customers.payload":        classify.None, // {"k": 1}: no personal keys or values
		"customers.status":         classify.None,
		"customers.notes":          classify.FreeText,
		"customers.amount_cents":   classify.None, // numbers are not sampled for phone shapes
		"customers.card_no":        classify.CardNumber,
		"customers.mobile_number":  classify.Phone,
		"customers.balance":        classify.None,
		"customers.email_tok":      classify.Email, // derived from email
		"events.id":                classify.None,
		"events.at":                classify.None,
		"emails.email":             classify.Email,
		"empty.email":              classify.Email,
		"contact_docs.id":          classify.None,
		"contact_docs.info":        classify.FreeText,
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
	if c := got[classification.Key{Schema: schema, Table: "customers", Column: "email_tok"}]; c.DerivedFrom != "email" {
		t.Errorf("email_tok derived_from %q, want email", c.DerivedFrom)
	}
	if c := got[classification.Key{Schema: schema, Table: "customers", Column: "contact"}]; c.DerivedFrom != "" {
		t.Errorf("contact derived_from %q, want none", c.DerivedFrom)
	}
	mv := got[classification.Key{Schema: schema, Table: "emails", Column: "email"}]
	if !strings.Contains(fmt.Sprint(mv.Evidence), "not populated") {
		t.Errorf("unpopulated materialized view evidence: %v", mv.Evidence)
	}
	for _, col := range []string{"email", "card_no", "mobile_number"} {
		if c := got[classification.Key{Schema: schema, Table: "customers", Column: col}]; c.Confidence != 0.95 {
			t.Errorf("%s confidence %.2f, want 0.95 (name and values agree): %v", col, c.Confidence, c.Evidence)
		}
	}
	if c := got[classification.Key{Schema: schema, Table: "customers", Column: "email"}]; !strings.Contains(fmt.Sprint(c.Evidence), "sampled all 50 rows") {
		t.Errorf("small table sampling evidence: %v", c.Evidence)
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

// TestScanSamplesWholeTablePostgres: the first rows of a table are often
// seed data or NULL in a column added later. A column that is NULL in its
// first tenth of the rows must still be recognized from its values, for
// each sampling method.
func TestScanSamplesWholeTablePostgres(t *testing.T) {
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
	const sch = "mps_sample"
	drop := func() { conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+sch+" CASCADE") }
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE SCHEMA " + sch,
		"CREATE TABLE " + sch + ".people (id int, contact text)",
		"INSERT INTO " + sch + ".people SELECT g, CASE WHEN g > 2000 THEN 'p' || g || '@example.com' END FROM generate_series(1, 20000) g",
		// Above the BERNOULLI threshold set below: pages are sampled.
		"CREATE TABLE " + sch + ".big (id int, contact text)",
		"INSERT INTO " + sch + ".big SELECT g, CASE WHEN g > 20000 THEN 'b' || g || '@example.com' END FROM generate_series(1, 200000) g",
		"ANALYZE " + sch + ".big",
		"ANALYZE " + sch + ".people",
		"CREATE TABLE " + sch + ".people_p (id int, contact text) PARTITION BY RANGE (id)",
		"CREATE TABLE " + sch + ".people_p1 PARTITION OF " + sch + ".people_p FOR VALUES FROM (0) TO (100000)",
		"INSERT INTO " + sch + ".people_p SELECT * FROM " + sch + ".people",
		"ANALYZE " + sch + ".people_p",
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	// big has about 900 pages: above this threshold it is sampled by page.
	defer func(v float64) { bernoulliMaxPages = v }(bernoulliMaxPages)
	bernoulliMaxPages = 500
	f, err := Postgres(ctx, conn, Options{Schemas: []string{sch}, SampleRows: 150})
	if err != nil {
		t.Fatal(err)
	}
	big := f.Index()[classification.Key{Schema: sch, Table: "big", Column: "contact"}]
	if big.Label != classify.Email || !strings.Contains(fmt.Sprint(big.Evidence), "TABLESAMPLE SYSTEM") {
		t.Errorf("big.contact: %s %v, want %s by TABLESAMPLE SYSTEM", big.Label, big.Evidence, classify.Email)
	}
	for _, table := range []string{"people", "people_p"} { // plain and partitioned
		c := f.Index()[classification.Key{Schema: sch, Table: table, Column: "contact"}]
		if c.Label != classify.Email {
			t.Errorf("%s.contact: %s %v, want %s", table, c.Label, c.Evidence, classify.Email)
		}
		if !strings.Contains(fmt.Sprint(c.Evidence), "TABLESAMPLE BERNOULLI") {
			t.Errorf("%s: evidence does not record the sampling method: %v", table, c.Evidence)
		}
	}
}
