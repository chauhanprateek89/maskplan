package scan

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
)

func TestScanMySQL(t *testing.T) {
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
	db.SetMaxOpenConns(1) // one session, so the setting below applies to the inserts
	if _, err := db.ExecContext(ctx, "SET SESSION cte_max_recursion_depth = 10000"); err != nil {
		t.Fatal(err)
	}
	const sch = "mps_scan"
	drop := func() { db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+sch) }
	drop()
	t.Cleanup(drop)
	for _, q := range []string{
		"CREATE DATABASE " + sch,
		"CREATE TABLE " + sch + `.customers (id int PRIMARY KEY, email varchar(100), contact text, phoneNumber varchar(32),
			iban varchar(40), ref varchar(30), last_seen_from varchar(45), dob date, dob_text varchar(10), created datetime,
			payload json, kyc json, status varchar(10), notes text, amount_cents bigint, card_no bigint, mobile_number bigint,
			balance decimal(12,2), email_verified tinyint(1), email_tok varchar(40), photo blob)`,
		// 500 rows: more than the sample, so sampled at random.
		"INSERT INTO " + sch + `.customers
			WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < 500)
			SELECT n, CONCAT('user', n, '@example.com'), CONCAT('c', n, '@example.ie'), CONCAT('+353 1 555 ', LPAD(n, 4, '0')),
				IF(n % 2 = 0, 'IE29AIBK93115212345678', 'GB82 WEST 1234 5698 7654 32'), IF(n % 2 = 0, '4111111111111111', '5500 0000 0000 0004'),
				CONCAT('192.168.1.', n % 250), DATE_ADD('1980-01-01', INTERVAL n DAY), '1980-01-01', NOW(),
				JSON_OBJECT('k', n), JSON_OBJECT('applicant', JSON_OBJECT('full_name', 'A B')), 'active', NULL, 1000000 + n,
				IF(n % 2 = 0, 4111111111111111, 5500000000000004), 353871230000 + n, 1000.5 + n, 1, CONCAT('tok_', MD5(n)), NULL
			FROM g`,
		// 5,000 rows, email NULL in the first 500: sampled by key range.
		"CREATE TABLE " + sch + ".people (id int PRIMARY KEY, contact varchar(100))",
		"INSERT INTO " + sch + `.people WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < 5000)
			SELECT n, IF(n > 500, CONCAT('p', n, '@example.com'), NULL) FROM g`,
		// The same without a primary key: one random pass.
		"CREATE TABLE " + sch + ".people_nopk (contact varchar(100))",
		"INSERT INTO " + sch + ".people_nopk SELECT contact FROM " + sch + ".people",
		"CREATE TABLE " + sch + ".empty (email varchar(100))",
		"CREATE VIEW " + sch + ".v AS SELECT email FROM " + sch + ".customers",
		"ANALYZE TABLE " + sch + ".customers, " + sch + ".people, " + sch + ".people_nopk",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	f, err := MySQL(ctx, db, Options{Schemas: []string{sch}, SampleRows: 20})
	if err != nil {
		t.Fatal(err)
	}
	got := f.Index()
	want := map[string]string{
		"customers.id": classify.None, "customers.email": classify.Email, "customers.contact": classify.Email,
		"customers.phoneNumber": classify.Phone, "customers.iban": classify.IBAN, "customers.ref": classify.CardNumber,
		"customers.last_seen_from": classify.IPAddress, "customers.dob": classify.BirthDate, "customers.dob_text": classify.None,
		"customers.created": classify.None, "customers.payload": classify.None, "customers.kyc": classify.FreeText,
		"customers.status": classify.None, "customers.notes": classify.FreeText, "customers.amount_cents": classify.None,
		"customers.card_no": classify.CardNumber, "customers.mobile_number": classify.Phone, "customers.balance": classify.None,
		"customers.email_verified": classify.None, "customers.email_tok": classify.Email, "customers.photo": classify.None,
		"people.id": classify.None, "people.contact": classify.Email, "people_nopk.contact": classify.Email,
		"empty.email": classify.Email,
	}
	for k, label := range want {
		p := strings.SplitN(k, ".", 2)
		c, ok := got[classification.Key{Schema: sch, Table: p[0], Column: p[1]}]
		if !ok {
			t.Errorf("%s not scanned", k)
			continue
		}
		if c.Label != label {
			t.Errorf("%s: %s (%.2f, %v), want %s", k, c.Label, c.Confidence, c.Evidence, label)
		}
	}
	if len(f.Columns) != len(want) {
		t.Errorf("scanned %d columns, want %d (views are skipped)", len(f.Columns), len(want))
	}
	for k, method := range map[string]string{
		"customers.email": "at random", "people.contact": "ranges of the primary key",
		"people_nopk.contact": "WHERE RAND()", "empty.email": "sampled all 0 rows",
	} {
		p := strings.SplitN(k, ".", 2)
		if ev := fmt.Sprint(got[classification.Key{Schema: sch, Table: p[0], Column: p[1]}].Evidence); !strings.Contains(ev, method) {
			t.Errorf("%s: evidence %s, want %q", k, ev, method)
		}
	}
	if c := got[classification.Key{Schema: sch, Table: "customers", Column: "email_tok"}]; c.DerivedFrom != "email" {
		t.Errorf("email_tok derived_from %q", c.DerivedFrom)
	}
	// The session time limit must not leak into the caller's pool.
	var limit int
	if err := db.QueryRowContext(ctx, "SELECT @@SESSION.MAX_EXECUTION_TIME").Scan(&limit); err != nil || limit != 0 {
		t.Errorf("MAX_EXECUTION_TIME left at %d (%v)", limit, err)
	}
}
