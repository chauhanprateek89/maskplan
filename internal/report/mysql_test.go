package report

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// The MySQL fixture mirrors the Postgres one: every privilege path the
// report must see, each given to its own account. Accounts and roles are
// server-wide, so all start with mpt_ and are dropped before and after.

var myTestDBs = []string{"mpt_data", "mpt_views", "mpt_masked", "mpt_fn", "mpt_sneaky", "mpt_internal"}

var myTestAccounts = []string{"mpt_reader", "mpt_mid", "mpt_mand", "mpt_direct", "mpt_table", "mpt_db", "mpt_wild", "mpt_global",
	"mpt_inherit", "mpt_default", "mpt_rawview", "mpt_nested", "mpt_joinview", "mpt_expr", "mpt_agg", "mpt_sub", "mpt_invoker",
	"mpt_clean", "mpt_sneaky", "mpt_secdef", "mpt_key", "mpt_keycol", "mpt_file", "mpt_repl", "mpt_proc", "mpt_proxy",
	"mpt_unlab", "mpt_derived", "mpt_mysqldb", "mpt_roleadmin", "mpt_tiny"}

func myClassification() *classification.File {
	f := &classification.File{Version: classification.Version}
	add := func(schema, table string, cols ...string) {
		for i := 0; i < len(cols); i += 2 {
			f.Columns = append(f.Columns, classification.Column{Schema: schema, Table: table, Column: cols[i], Label: cols[i+1], Reviewed: true})
		}
	}
	add("mpt_data", "customers", "id", classify.None, "email", classify.Email, "name", classify.Name, "phone", classify.Phone)
	add("mpt_data", "orders", "id", classify.None, "customer_id", classify.None)
	add("mpt_data", "tiny", "id", classify.None, "email", classify.Email)
	add("mpt_data", "contacts", "id", classify.None, "email", classify.Email, "email_tok", classify.Email)
	f.Columns[len(f.Columns)-1].DerivedFrom = "email"
	return f
}

func myExec(t *testing.T, db *sql.DB, qs ...string) {
	t.Helper()
	for _, q := range qs {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
}

func myDrop(db *sql.DB) {
	db.Exec("SET GLOBAL mandatory_roles = ''")
	for _, a := range myTestAccounts {
		db.Exec("DROP USER IF EXISTS " + a + "@'%'")
	}
	for _, d := range myTestDBs {
		db.Exec("DROP DATABASE IF EXISTS " + d)
	}
}

func myFixture(t *testing.T) (*sql.DB, *mysql.Config) {
	t.Helper()
	dsn := os.Getenv("MASKPLAN_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_MYSQL_DSN not set")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	myDrop(db)
	t.Cleanup(func() { myDrop(db) })

	for _, d := range myTestDBs {
		myExec(t, db, "CREATE DATABASE "+d)
	}
	for _, a := range myTestAccounts {
		myExec(t, db, "CREATE USER "+a+"@'%' IDENTIFIED BY 'mpt-test-pw'")
	}
	ipad, opad := token.Pads(testKey)
	myExec(t, db,
		"CREATE TABLE mpt_internal.key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad VARBINARY(64) NOT NULL, opad VARBINARY(64) NOT NULL)",
		"CREATE TABLE mpt_data.customers (id int PRIMARY KEY, email varchar(100), name varchar(100), phone varchar(32))",
		// More than one row: the optimizer reads one-row tables as constants.
		"INSERT INTO mpt_data.customers VALUES (1, 'alice@example.com', 'Alice', '+353 1 234 5678'), (2, 'bob@example.com', 'Bob', '+353 1 234 5679'), (3, 'carol@example.com', 'Carol', '01 234 5670')",
		"CREATE TABLE mpt_data.orders (id int PRIMARY KEY, customer_id int)",
		"INSERT INTO mpt_data.orders VALUES (1, 1), (2, 2), (3, 3)",
		"CREATE TABLE mpt_data.unlabeled (id int, secret_notes text)",
		"CREATE TABLE mpt_data.tiny (id int PRIMARY KEY, email varchar(100))",
		"INSERT INTO mpt_data.tiny VALUES (1, 'only@example.com')",
		"CREATE TABLE mpt_data.contacts (id int, email varchar(100), email_tok varchar(40))",
		"CREATE TABLE mpt_sneaky.key_material (id smallint PRIMARY KEY, ipad VARBINARY(64), opad VARBINARY(64))",
	)
	if _, err := db.Exec("INSERT INTO mpt_internal.key_material VALUES (1, ?, ?)", ipad, opad); err != nil {
		t.Fatal(err)
	}
	myExec(t, db, "INSERT INTO mpt_sneaky.key_material SELECT * FROM mpt_internal.key_material", "ANALYZE TABLE mpt_data.customers, mpt_data.orders")

	from, pads, _ := sqlexpr.KeySource(sqlexpr.MySQL, "mpt_internal.key_material", "k")
	tok := func(expr, label string, n token.Normalizer, p sqlexpr.Pads) string {
		s, err := sqlexpr.Token(sqlexpr.MySQL, sqlexpr.Column{Expr: expr, Label: label, Normalizer: n}, p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	email := tok("c.email", classify.Email, token.Email, pads)
	myExec(t, db,
		"CREATE VIEW mpt_views.contacts AS SELECT id, email FROM mpt_data.customers",
		"CREATE VIEW mpt_views.contacts_nested AS SELECT id, email FROM mpt_views.contacts",
		"CREATE VIEW mpt_views.order_names AS SELECT o.id, c.name AS customer FROM mpt_data.orders o JOIN mpt_data.customers c ON c.id = o.customer_id",
		"CREATE VIEW mpt_views.shouting AS SELECT id, upper(email) AS email FROM mpt_data.customers",
		"CREATE VIEW mpt_views.agg AS SELECT count(*) AS n, max(email) AS email FROM mpt_data.customers",
		"CREATE VIEW mpt_views.sub AS SELECT o.id, (SELECT c.email FROM mpt_data.customers c WHERE c.id = o.customer_id) AS email FROM mpt_data.orders o",
		"CREATE SQL SECURITY INVOKER VIEW mpt_views.invoker AS SELECT id, email FROM mpt_data.customers",
		"CREATE VIEW mpt_views.tiny AS SELECT id, email FROM mpt_data.tiny",
		"CREATE VIEW mpt_views.contact_tokens AS SELECT id, email_tok FROM mpt_data.contacts",
		fmt.Sprintf("CREATE VIEW mpt_masked.customers AS SELECT c.id, %s AS email, %s AS phone FROM mpt_data.customers c %s",
			email, tok("c.phone", classify.Phone, token.Phone, pads), from),
		fmt.Sprintf("CREATE VIEW mpt_sneaky.coalesce_token AS SELECT c.id, coalesce(c.email, %s) AS email FROM mpt_data.customers c %s", email, from),
		fmt.Sprintf("CREATE VIEW mpt_sneaky.token_concat AS SELECT c.id, concat(%s, c.email) AS email FROM mpt_data.customers c %s", email, from),
		// Passes every shape check (label, length, key table, one base
		// column) but its first 16 characters are the email itself.
		"CREATE VIEW mpt_sneaky.leaky_left AS SELECT c.id, concat('tok_', left(concat(c.email, sha2(concat(k.opad, unhex(sha2(concat(k.ipad, 'user.contact.email:'), 256))), 256)), 16)) AS email FROM mpt_data.customers c JOIN mpt_internal.key_material k ON k.id = 1",
		// A primary-key filter makes the optimizer read the row as a constant.
		"CREATE VIEW mpt_views.one_row AS SELECT id, email FROM mpt_data.customers WHERE id = 1",
		"CREATE VIEW mpt_sneaky.fakemask AS SELECT id, concat('tok_', left(sha2(sha2(email, 256), 256), 16)) AS email FROM mpt_data.customers",
		fmt.Sprintf("CREATE VIEW mpt_sneaky.copied_key AS SELECT c.id, %s AS email FROM mpt_data.customers c JOIN mpt_sneaky.key_material k ON k.id = 1",
			tok("c.email", classify.Email, token.Email, sqlexpr.Pads{IPad: "k.ipad", OPad: "k.opad"})),
		"CREATE FUNCTION mpt_fn.customer_email(i int) RETURNS varchar(100) READS SQL DATA SQL SECURITY DEFINER RETURN (SELECT email FROM mpt_data.customers WHERE id = i)",
		"CREATE FUNCTION mpt_fn.invoker_email(i int) RETURNS varchar(100) READS SQL DATA SQL SECURITY INVOKER RETURN (SELECT email FROM mpt_data.customers WHERE id = i)",
	)

	// One path per account.
	myExec(t, db,
		"GRANT SELECT ON mpt_data.customers TO mpt_reader@'%'",
		"GRANT mpt_reader@'%' TO mpt_mid@'%'",
		"GRANT mpt_mid@'%' TO mpt_inherit@'%'",
		"GRANT mpt_reader@'%' TO mpt_default@'%'",
		"SET DEFAULT ROLE mpt_reader@'%' TO mpt_default@'%'",
		"GRANT SELECT (id, email) ON mpt_data.customers TO mpt_direct@'%'",
		"GRANT SELECT ON mpt_data.customers TO mpt_table@'%'",
		"GRANT SELECT ON mpt_data.* TO mpt_db@'%'",
		"GRANT SELECT ON `mpt\\_d%`.* TO mpt_wild@'%'",
		"GRANT SELECT ON *.* TO mpt_global@'%'",
		"GRANT SELECT ON mpt_views.contacts TO mpt_rawview@'%'",
		"GRANT SELECT ON mpt_views.contacts_nested TO mpt_nested@'%'",
		"GRANT SELECT ON mpt_views.order_names TO mpt_joinview@'%'",
		"GRANT SELECT ON mpt_views.shouting TO mpt_expr@'%'",
		"GRANT SELECT ON mpt_views.agg TO mpt_agg@'%'",
		"GRANT SELECT ON mpt_views.sub TO mpt_sub@'%'",
		"GRANT SELECT ON mpt_views.invoker TO mpt_invoker@'%'",
		"GRANT SELECT ON mpt_views.tiny TO mpt_tiny@'%'",
		"GRANT SELECT ON mpt_masked.customers TO mpt_clean@'%'",
		"GRANT EXECUTE ON FUNCTION mpt_fn.invoker_email TO mpt_clean@'%'",
		"GRANT SELECT ON mpt_sneaky.coalesce_token TO mpt_sneaky@'%'",
		"GRANT SELECT ON mpt_sneaky.token_concat TO mpt_sneaky@'%'",
		"GRANT SELECT ON mpt_sneaky.fakemask TO mpt_sneaky@'%'",
		"GRANT SELECT ON mpt_sneaky.leaky_left TO mpt_sneaky@'%'",
		"GRANT SELECT ON mpt_views.one_row TO mpt_tiny@'%'",
		"GRANT SELECT ON mpt_sneaky.copied_key TO mpt_sneaky@'%'",
		"GRANT EXECUTE ON FUNCTION mpt_fn.customer_email TO mpt_secdef@'%'",
		"GRANT SELECT ON mpt_internal.key_material TO mpt_key@'%'",
		"GRANT SELECT (ipad) ON mpt_internal.key_material TO mpt_keycol@'%'",
		"GRANT FILE ON *.* TO mpt_file@'%'",
		"GRANT REPLICATION SLAVE ON *.* TO mpt_repl@'%'",
		"GRANT PROCESS ON *.* TO mpt_proc@'%'",
		"GRANT SELECT ON mpt_data.unlabeled TO mpt_unlab@'%'",
		"GRANT SELECT (id, email_tok) ON mpt_data.contacts TO mpt_derived@'%'",
		"GRANT SELECT ON mpt_views.contact_tokens TO mpt_derived@'%'",
		"GRANT SELECT ON mysql.user TO mpt_mysqldb@'%'",
		"GRANT ROLE_ADMIN ON *.* TO mpt_roleadmin@'%'",
	)
	myExec(t, db, proxyGrant("mpt_proxy", "mpt_table"))
	myExec(t, db, "FLUSH PRIVILEGES")
	return db, cfg
}

// proxyGrant writes the row GRANT PROXY would. GRANT PROXY needs the
// grantor to hold PROXY WITH GRANT OPTION, which only root@localhost has by
// default; the report reads the table, so the row is what matters.
func proxyGrant(user, proxied string) string {
	return fmt.Sprintf("INSERT INTO mysql.proxies_priv (Host, User, Proxied_host, Proxied_user, With_grant, Grantor) VALUES ('%%', '%s', '%%', '%s', 0, 'maskplan-test@%%')", user, proxied)
}

func myReport(t *testing.T, db *sql.DB, account string) *Report {
	t.Helper()
	r, err := MySQL(context.Background(), db, account, myClassification(), Options{Schemas: []string{"mpt_data", "mpt_views", "mpt_masked", "mpt_fn", "mpt_sneaky"}, InternalSchema: "mpt_internal"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportMySQL(t *testing.T) {
	db, cfg := myFixture(t)
	const email, name, phone = "mpt_data.customers.email", "mpt_data.customers.name", "mpt_data.customers.phone"
	const key = "mpt_internal.key_material"
	cases := []struct {
		account string
		want    []expect
		mustNot []string
		pass    bool
	}{
		{"mpt_direct", []expect{{Raw, email, []string{"SELECT on the column granted to 'mpt_direct'@'%'"}}}, []string{name, phone}, false},
		{"mpt_table", []expect{{Raw, email, []string{"SELECT on the table"}}, {Raw, name, nil}, {Raw, phone, nil}}, nil, false},
		{"mpt_db", []expect{{Raw, email, []string{"SELECT on `mpt_data`.*"}}}, nil, false},
		{"mpt_wild", []expect{{Raw, email, []string{"SELECT on `mpt\\_d%`.*"}}}, nil, false},
		{"mpt_global", []expect{{Raw, email, []string{"global SELECT"}}, {Key, key, nil}, {Unknown, "mysql.user", []string{"password hashes"}}}, nil, false},
		{"mpt_inherit", []expect{{Raw, email, []string{"usable with SET ROLE: 'mpt_inherit'@'%' > 'mpt_mid'@'%' > 'mpt_reader'@'%'"}}}, nil, false},
		{"mpt_default", []expect{{Raw, email, []string{"active at login"}}}, nil, false},
		{"mpt_rawview", []expect{{Raw, "mpt_views.contacts.email", []string{"passes through " + email}}}, []string{email}, false},
		{"mpt_nested", []expect{{Raw, "mpt_views.contacts_nested.email", []string{"passes through " + email}}}, nil, false},
		{"mpt_joinview", []expect{{Raw, "mpt_views.order_names.customer", []string{"passes through " + name}}}, nil, false},
		{"mpt_expr", []expect{{Unknown, "mpt_views.shouting.email", []string{"not a maskplan token"}}}, nil, false},
		{"mpt_agg", []expect{{Unknown, "mpt_views.agg.email", nil}}, nil, false},
		{"mpt_sub", []expect{{Unknown, "mpt_views.sub.email", nil}}, nil, false},
		{"mpt_invoker", []expect{{Raw, "mpt_views.invoker.email", nil}}, nil, false},
		// One row, but InnoDB still reads it as a table: the reference survives.
		{"mpt_tiny", []expect{
			{Raw, "mpt_views.tiny.email", []string{"passes through mpt_data.tiny.email"}},
			{Unknown, "mpt_views.one_row.email", []string{"constant"}},
		}, nil, false},
		{"mpt_clean", []expect{
			{Masked, "mpt_masked.customers.email", []string{"maskplan token of " + email}},
			{Masked, "mpt_masked.customers.phone", []string{"maskplan token of " + phone}},
		}, []string{email, phone}, true},
		{"mpt_sneaky", []expect{
			{Unknown, "mpt_sneaky.coalesce_token.email", nil}, {Unknown, "mpt_sneaky.token_concat.email", nil},
			{Unknown, "mpt_sneaky.fakemask.email", nil}, {Unknown, "mpt_sneaky.copied_key.email", nil},
			{Unknown, "mpt_sneaky.leaky_left.email", nil},
		}, []string{email}, false},
		{"mpt_secdef", []expect{{Unknown, "function mpt_fn.customer_email", []string{"SQL SECURITY DEFINER", "EXECUTE on the routine"}}}, nil, false},
		{"mpt_key", []expect{{Key, key, []string{"SELECT on the table"}}}, nil, false},
		{"mpt_keycol", []expect{{Key, key, []string{"SELECT on the column"}}}, nil, false},
		{"mpt_file", []expect{{Unknown, "account", []string{"FILE"}}}, nil, false},
		{"mpt_repl", []expect{{Unknown, "account", []string{"REPLICATION SLAVE"}}}, nil, false},
		{"mpt_proc", []expect{{Warn, "account", []string{"PROCESS"}}}, nil, true},
		{"mpt_proxy", []expect{{Unknown, "account", []string{"PROXY", "'mpt_table'@'%'"}}}, nil, false},
		{"mpt_unlab", []expect{{Unlabeled, "mpt_data.unlabeled.secret_notes", nil}}, nil, false},
		{"mpt_derived", []expect{
			{Unknown, "mpt_data.contacts.email_tok", []string{"not verified"}},
			{Unknown, "mpt_views.contact_tokens.email_tok", []string{"not verified"}},
		}, []string{"mpt_data.contacts.email"}, false},
		{"mpt_mysqldb", []expect{{Unknown, "mysql.user", []string{"password hashes"}}}, nil, false},
		{"mpt_roleadmin", []expect{{Unknown, "account", []string{"ROLE_ADMIN"}}}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.account, func(t *testing.T) {
			r := myReport(t, db, c.account+"@%")
			for _, e := range c.want {
				found := false
				for _, f := range r.Findings {
					found = found || e.matches(f)
				}
				if !found {
					t.Errorf("missing %s %s (path containing %q)", e.status, e.object, e.path)
				}
			}
			for _, f := range r.Findings {
				noSecrets(t, f)
				for _, o := range c.mustNot {
					if f.Object == o && (f.Status == Raw || f.Status == Unknown || f.Status == Key) {
						t.Errorf("unexpected %s %s: %s", f.Status, f.Object, f.Path)
					}
				}
				if f.Status == Masked && !strings.HasPrefix(f.Object, "mpt_masked.") {
					t.Errorf("MASKED outside the masked schema: %s: %s", f.Object, f.Path)
				}
			}
			if r.Failed() == c.pass {
				t.Errorf("Failed() = %v, want %v", r.Failed(), !c.pass)
			}
			if t.Failed() {
				t.Log("\n" + dump(r))
			}
		})
	}

	// A key written into a view definition fails every account, as on
	// Postgres, so it gets its own subtest.
	t.Run("key literal in a view", func(t *testing.T) {
		ipad, opad := token.Pads(testKey)
		e, err := sqlexpr.Token(sqlexpr.MySQL, sqlexpr.Column{Expr: "c.email", Label: classify.Email, Normalizer: token.Email},
			sqlexpr.Pads{IPad: fmt.Sprintf("0x%x", ipad), OPad: fmt.Sprintf("0x%x", opad)})
		if err != nil {
			t.Fatal(err)
		}
		myExec(t, db, "CREATE VIEW mpt_sneaky.literal_key AS SELECT c.id, "+e+" AS email FROM mpt_data.customers c",
			"GRANT SELECT ON mpt_sneaky.literal_key TO mpt_sneaky@'%'")
		defer myExec(t, db, "DROP VIEW mpt_sneaky.literal_key")
		for _, c := range []struct {
			account string
			want    expect
		}{
			{"mpt_clean@%", expect{Key, "view mpt_sneaky.literal_key", []string{"definition contains the token key material"}}},
			{"mpt_sneaky@%", expect{Unknown, "mpt_sneaky.literal_key.email", nil}},
		} {
			r := myReport(t, db, c.account)
			found := false
			for _, f := range r.Findings {
				noSecrets(t, f)
				found = found || c.want.matches(f)
				if f.Status == Masked && !strings.HasPrefix(f.Object, "mpt_masked.") {
					t.Errorf("MASKED outside the masked schema: %s", f.Object)
				}
			}
			if !found || !r.Failed() {
				t.Errorf("%s: missing %s %s\n%s", c.account, c.want.status, c.want.object, dump(r))
			}
		}
	})

	t.Run("mandatory role", func(t *testing.T) {
		myExec(t, db, "GRANT SELECT ON mpt_data.customers TO mpt_mand@'%'", "SET GLOBAL mandatory_roles = 'mpt_mand@%'")
		defer myExec(t, db, "SET GLOBAL mandatory_roles = ''", "REVOKE SELECT ON mpt_data.customers FROM mpt_mand@'%'")
		r := myReport(t, db, "mpt_clean@%")
		found := false
		for _, f := range r.Findings {
			found = found || (expect{Raw, email, []string{"mandatory role"}}).matches(f)
		}
		if !found || !r.Failed() {
			t.Errorf("mandatory role not seen:\n%s", dump(r))
		}
	})

	t.Run("clean account really reads tokens only", func(t *testing.T) {
		c := cfg.Clone()
		c.User, c.Passwd, c.DBName = "mpt_clean", "mpt-test-pw", ""
		agent, err := sql.Open("mysql", c.FormatDSN())
		if err != nil {
			t.Fatal(err)
		}
		defer agent.Close()
		var got string
		if err := agent.QueryRow("SELECT email FROM mpt_masked.customers WHERE id = 1").Scan(&got); err != nil {
			t.Fatal(err)
		}
		v := "alice@example.com"
		if want := *token.Token(testKey, classify.Email, token.Email, &v); got != want {
			t.Errorf("masked view returned %q, want %q", got, want)
		}
		if err := agent.QueryRow("SELECT email FROM mpt_data.customers LIMIT 1").Scan(&got); err == nil {
			t.Error("mpt_clean read mpt_data.customers directly")
		}
	})

	mutations := []struct{ name, apply, revert string }{
		{"granted role", "GRANT mpt_reader@'%' TO mpt_clean@'%'", "REVOKE mpt_reader@'%' FROM mpt_clean@'%'"},
		{"aggregate view", "GRANT SELECT ON mpt_views.agg TO mpt_clean@'%'", "REVOKE SELECT ON mpt_views.agg FROM mpt_clean@'%'"},
		{"key column", "GRANT SELECT (opad) ON mpt_internal.key_material TO mpt_clean@'%'", "REVOKE SELECT (opad) ON mpt_internal.key_material FROM mpt_clean@'%'"},
		{"definer function", "GRANT EXECUTE ON FUNCTION mpt_fn.customer_email TO mpt_clean@'%'", "REVOKE EXECUTE ON FUNCTION mpt_fn.customer_email FROM mpt_clean@'%'"},
		{"wildcard database", "GRANT SELECT ON `mpt\\_dat_`.* TO mpt_clean@'%'", "REVOKE SELECT ON `mpt\\_dat_`.* FROM mpt_clean@'%'"},
		{"file", "GRANT FILE ON *.* TO mpt_clean@'%'", "REVOKE FILE ON *.* FROM mpt_clean@'%'"},
		{"proxy", proxyGrant("mpt_clean", "mpt_table"), "DELETE FROM mysql.proxies_priv WHERE User = 'mpt_clean'"},
		{"replication", "GRANT REPLICATION SLAVE ON *.* TO mpt_clean@'%'", "REVOKE REPLICATION SLAVE ON *.* FROM mpt_clean@'%'"},
		{"column of a raw table", "GRANT SELECT (phone) ON mpt_data.customers TO mpt_clean@'%'", "REVOKE SELECT (phone) ON mpt_data.customers FROM mpt_clean@'%'"},
		{"global select", "GRANT SELECT ON *.* TO mpt_clean@'%'", "REVOKE SELECT ON *.* FROM mpt_clean@'%'"},
	}
	for _, m := range mutations {
		t.Run("mutation/"+m.name, func(t *testing.T) {
			myExec(t, db, m.apply, "FLUSH PRIVILEGES")
			defer myExec(t, db, m.revert, "FLUSH PRIVILEGES")
			if r := myReport(t, db, "mpt_clean@%"); !r.Failed() {
				t.Errorf("report passed mpt_clean after %s\n%s", m.apply, dump(r))
			}
		})
	}
	t.Run("clean again after mutations", func(t *testing.T) {
		if r := myReport(t, db, "mpt_clean@%"); r.Failed() {
			t.Errorf("mutations were not reverted:\n%s", dump(r))
		}
	})
	t.Run("account by user name alone", func(t *testing.T) {
		if r := myReport(t, db, "mpt_clean"); r.Role != "'mpt_clean'@'%'" {
			t.Errorf("role %q", r.Role)
		}
	})
}

// noSecrets fails if a finding repeats a value from the fixture's data or
// the key: reports are pasted into CI logs and pull requests.
func noSecrets(t *testing.T, f Finding) {
	t.Helper()
	ipad, opad := token.Pads(testKey)
	for _, v := range []string{"alice@example", "bob@example", "carol@example", "only@example", "Alice", "+353 1 234",
		fmt.Sprintf("%x", ipad)[:16], fmt.Sprintf("%x", opad)[:16]} {
		if strings.Contains(f.Object+" "+f.Path, v) {
			t.Errorf("finding repeats %q: %s %s: %s", v, f.Status, f.Object, f.Path)
		}
	}
}
