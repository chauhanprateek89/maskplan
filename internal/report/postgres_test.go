package report

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// The fixture below builds one database with every privilege path the
// report must see, each given to its own role. Roles are cluster-wide, so
// they all start with mpt_ and are dropped before and after the test.

const testInternal = "mpt_internal"

const (
	extAddMember  = "ALTER EXTENSION postgres_fdw ADD FUNCTION mpt_fn.ext_email(int)"
	extDropMember = "ALTER EXTENSION postgres_fdw DROP FUNCTION mpt_fn.ext_email(int)"
	extDropView   = "ALTER EXTENSION postgres_fdw DROP VIEW mpt_fn.ext_catalog"
)

var testSchemas = []string{"mpt_data", "mpt_pub", "mpt_views", "mpt_masked", "mpt_fn", "mpt_sneaky", "mpt_parts"}

// sneakyViews look like, or contain, maskplan tokens but return raw data or
// cannot be traced. Every column must come out UNKNOWN, never MASKED. The
// first five defeated the first version of the report (NOTES.md).
var sneakyViews = []string{"coalesce_token", "token_concat", "newline_literal", "whole_row", "init_plan",
	"union_all", "cte", "copied_key_table", "aggregate", "authid", "fake_fallback", "long_prefix", "part_mixed"}

var testKey = []byte("report-test-key-0123456789abcdef")

func testClassification() *classification.File {
	f := &classification.File{Version: classification.Version}
	add := func(schema, table string, cols ...string) {
		for i := 0; i < len(cols); i += 2 {
			f.Columns = append(f.Columns, classification.Column{Schema: schema, Table: table, Column: cols[i], Label: cols[i+1], Reviewed: true})
		}
	}
	add("mpt_data", "customers", "id", classify.None, "email", classify.Email, "name", classify.Name, "phone", classify.Phone)
	add("mpt_data", "accounts", "id", classify.None, "customer_id", classify.None, "iban", classify.IBAN)
	add("mpt_data", "orders", "id", classify.None, "customer_id", classify.None, "total", classify.None)
	add("mpt_data", "events", "id", classify.None, "ip", classify.IPAddress, "at", classify.None)
	add("mpt_data", "customer_mv", "id", classify.None, "email", classify.Email)
	add("mpt_pub", "leads", "id", classify.None, "email", classify.Email)
	add("mpt_data", "contacts", "id", classify.None, "email", classify.Email, "email_tok", classify.Email)
	f.Columns[len(f.Columns)-1].DerivedFrom = "email"
	return f
}

func pgTestConn(t *testing.T) (*pgx.Conn, int) {
	t.Helper()
	dsn := os.Getenv("MASKPLAN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) }) // runs after the fixture's cleanup
	var version int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return conn, version
}

func exec(t *testing.T, conn *pgx.Conn, qs ...string) {
	t.Helper()
	for _, q := range qs {
		if _, err := conn.Exec(context.Background(), q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
}

func dropFixture(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	// The extension member must leave the extension first, or dropping its
	// schema would take postgres_fdw with it.
	var fnMember, viewMember bool
	if err := conn.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM pg_depend WHERE classid = 'pg_proc'::regclass AND objid = to_regprocedure('mpt_fn.ext_email(int)') AND deptype = 'e'),
		EXISTS (SELECT 1 FROM pg_depend WHERE classid = 'pg_class'::regclass AND objid = to_regclass('mpt_fn.ext_catalog') AND deptype = 'e')`).Scan(&fnMember, &viewMember); err != nil {
		t.Fatal(err)
	}
	if fnMember {
		exec(t, conn, extDropMember)
	}
	if viewMember {
		exec(t, conn, extDropView)
	}
	for _, s := range append([]string{testInternal}, testSchemas...) {
		exec(t, conn, "DROP SCHEMA IF EXISTS "+s+" CASCADE")
	}
	var fdw bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_foreign_data_wrapper WHERE fdwname = 'postgres_fdw')").Scan(&fdw); err != nil {
		t.Fatal(err)
	}
	if fdw {
		exec(t, conn, "DROP SERVER IF EXISTS mpt_loop CASCADE")
	}
	rows, err := conn.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname LIKE 'mpt\_%' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		// DROP OWNED also removes default privileges and grants to r.
		exec(t, conn, "DROP OWNED BY "+r+" CASCADE")
	}
	for _, r := range roles {
		exec(t, conn, "DROP ROLE "+r)
	}
}

// fixture creates the database objects and roles. It reports whether
// postgres_fdw was available.
func fixture(t *testing.T, conn *pgx.Conn, version int) bool {
	t.Helper()
	ctx := context.Background()
	dropFixture(t, conn)
	t.Cleanup(func() { dropFixture(t, conn) })

	from, pads, err := sqlexpr.KeySource(sqlexpr.Postgres, testInternal+".key_material", "k")
	if err != nil {
		t.Fatal(err)
	}
	tok := func(expr, label string, n token.Normalizer) string {
		s, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{Expr: expr, Label: label, Normalizer: n}, pads)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	roles := []string{
		"mpt_reader NOLOGIN", "mpt_mid NOLOGIN", "mpt_owner NOLOGIN",
		"mpt_direct", "mpt_table", "mpt_public", "mpt_inherit", "mpt_noinherit NOINHERIT", "mpt_ownmember",
		"mpt_super SUPERUSER", "mpt_rawview", "mpt_nested", "mpt_joinview", "mpt_expr", "mpt_subquery",
		"mpt_barrier", "mpt_fakemask", "mpt_clean", "mpt_secdef", "mpt_defpriv", "mpt_fdw", "mpt_key",
		"mpt_keycol", "mpt_part", "mpt_matview", "mpt_unlab", "mpt_createrole CREATEROLE", "mpt_srvfiles",
		"mpt_readall", "mpt_nouse", "mpt_sneaky", "mpt_repl REPLICATION", "mpt_stats", "mpt_derived",
	}
	for _, r := range roles {
		exec(t, conn, "CREATE ROLE "+r)
	}
	for _, s := range append([]string{testInternal}, testSchemas...) {
		exec(t, conn, "CREATE SCHEMA "+s)
	}
	ipad, opad := token.Pads(testKey)
	tokWith := func(expr string, p sqlexpr.Pads) string {
		s, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{Expr: expr, Label: classify.Email, Normalizer: token.Email}, p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	fakeIndex := func(expr string) string {
		s, err := sqlexpr.FakeIndex(sqlexpr.Postgres, sqlexpr.Column{Expr: expr, Label: classify.Email, Normalizer: token.Email}, pads, compile.DictionarySize)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	exec(t, conn,
		"CREATE TABLE mpt_internal.key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad bytea NOT NULL, opad bytea NOT NULL)",
		"CREATE TABLE mpt_internal.names (i int PRIMARY KEY, name text NOT NULL)",
		"CREATE TABLE mpt_data.customers (id int PRIMARY KEY, email text, name text, phone text)",
		"INSERT INTO mpt_data.customers VALUES (1, 'alice@example.com', 'Alice', '+353 1 234 5678')",
		"CREATE TABLE mpt_data.accounts (id int PRIMARY KEY, customer_id int, iban text)",
		"CREATE TABLE mpt_data.orders (id int PRIMARY KEY, customer_id int, total numeric)",
		"CREATE TABLE mpt_data.events (id int, ip inet, at date) PARTITION BY RANGE (at)",
		"CREATE TABLE mpt_data.events_2026 PARTITION OF mpt_data.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')",
		// A partition in another schema than its root, as GitLab keeps them.
		"CREATE TABLE mpt_parts.events_2027 PARTITION OF mpt_data.events FOR VALUES FROM ('2027-01-01') TO ('2028-01-01')",
		"CREATE MATERIALIZED VIEW mpt_data.customer_mv AS SELECT id, email FROM mpt_data.customers",
		"CREATE TABLE mpt_data.unlabeled (id int, secret_notes text)",
		"CREATE TABLE mpt_data.contacts (id int, email text, email_tok text)",
		"CREATE VIEW mpt_views.contact_tokens AS SELECT id, email_tok FROM mpt_data.contacts",
		"CREATE TABLE mpt_pub.leads (id int, email text)",
	)
	if _, err := conn.Exec(ctx, "INSERT INTO mpt_internal.key_material VALUES (1, $1, $2)", ipad, opad); err != nil {
		t.Fatal(err)
	}
	exec(t, conn,
		// Views, all owned by the inspecting user, who can read everything.
		"CREATE VIEW mpt_views.contacts AS SELECT id, email FROM mpt_data.customers",
		"CREATE VIEW mpt_views.contacts_nested AS SELECT id, email FROM mpt_views.contacts",
		"CREATE VIEW mpt_views.order_names AS SELECT o.id, c.name AS customer FROM mpt_data.orders o JOIN mpt_data.customers c ON c.id = o.customer_id",
		"CREATE VIEW mpt_views.shouting AS SELECT id, upper(email) AS email FROM mpt_data.customers",
		"CREATE VIEW mpt_views.order_emails AS SELECT o.id, (SELECT c.email FROM mpt_data.customers c WHERE c.id = o.customer_id) AS email FROM mpt_data.orders o",
		"CREATE VIEW mpt_views.barrier WITH (security_barrier) AS SELECT id, email FROM mpt_data.customers",
		// Looks like a token (two sha256 calls, tok_ prefix) but has no key:
		// anyone can hash guessed emails.
		"CREATE VIEW mpt_views.fakemask AS SELECT id, 'tok_' || left(encode(sha256(sha256(convert_to(email, 'UTF8'))), 'hex'), 16) AS email FROM mpt_data.customers",
		// The fake name's join comes before the tokens, so reading one
		// column leaves unused InitPlans in the plan (canonicalPlan).
		fmt.Sprintf("CREATE VIEW mpt_masked.customers AS SELECT c.id, fake_email.name AS fake_email, %s AS email, %s AS phone, left(c.phone, 3) AS phone_prefix FROM mpt_data.customers c LEFT JOIN mpt_internal.names fake_email ON fake_email.i = %s %s",
			tok("c.email", classify.Email, token.Email), tok("c.phone", classify.Phone, token.Phone), fakeIndex("c.email"), from),
		"CREATE TABLE mpt_sneaky.key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad bytea NOT NULL, opad bytea NOT NULL)",
		"INSERT INTO mpt_sneaky.key_material SELECT * FROM mpt_internal.key_material",
		fmt.Sprintf("CREATE VIEW mpt_sneaky.coalesce_token AS SELECT coalesce(c.email, %s) AS email FROM mpt_data.customers c %s", tok("c.email", classify.Email, token.Email), from),
		fmt.Sprintf("CREATE VIEW mpt_sneaky.token_concat AS SELECT %s || c.email AS email FROM mpt_data.customers c %s", tok("c.email", classify.Email, token.Email), from),
		// A newline literal splits EXPLAIN's text output across rows.
		`CREATE VIEW mpt_sneaky.newline_literal AS SELECT coalesce(nullif(E'\n', ''), '') || c.email AS email FROM mpt_data.customers c`,
		"CREATE VIEW mpt_sneaky.whole_row AS SELECT row_to_json(c) AS email FROM mpt_data.customers c",
		"CREATE VIEW mpt_sneaky.init_plan AS SELECT o.id, (SELECT email FROM mpt_data.customers LIMIT 1) AS email FROM mpt_data.orders o",
		"CREATE VIEW mpt_sneaky.union_all AS SELECT email FROM mpt_data.customers UNION ALL SELECT email FROM mpt_pub.leads",
		"CREATE VIEW mpt_sneaky.cte AS WITH x AS MATERIALIZED (SELECT email FROM mpt_data.customers) SELECT email FROM x",
		fmt.Sprintf("CREATE VIEW mpt_sneaky.copied_key_table AS SELECT %s AS email FROM mpt_data.customers c",
			tokWith("c.email", sqlexpr.Pads{IPad: "(SELECT ipad FROM mpt_sneaky.key_material)", OPad: "(SELECT opad FROM mpt_sneaky.key_material)"})),
		"CREATE VIEW mpt_sneaky.aggregate AS SELECT string_agg(email, ',') AS email FROM mpt_data.customers",
		// A fake name that falls back to the raw value when the join misses.
		fmt.Sprintf("CREATE VIEW mpt_sneaky.fake_fallback AS SELECT coalesce(fake_email.name, c.email) AS email FROM mpt_data.customers c LEFT JOIN mpt_internal.names fake_email ON fake_email.i = %s", fakeIndex("c.email")),
		// A fake name indexed by another column than its alias claims: not
		// raw, but not what maskplan generates either.
		fmt.Sprintf("CREATE VIEW mpt_sneaky.fake_other_column AS SELECT fake_email.name AS email FROM mpt_data.customers c LEFT JOIN mpt_internal.names fake_email ON fake_email.i = %s", fakeIndex("c.name")),
		// Selecting id still runs the condition on every email; the cast's
		// error message carries the value.
		"CREATE VIEW mpt_sneaky.cast_error AS SELECT c.id FROM mpt_data.customers c WHERE c.email::int > 0",
		// A condition on a column that is not personal data: no finding.
		"CREATE VIEW mpt_masked.big_orders AS SELECT id FROM mpt_data.orders WHERE total > 100",
		"GRANT SELECT ON mpt_masked.big_orders TO mpt_clean",
		// Two partitions of one table, one tokenized and one raw: not a read
		// of the partitioned table, whose members all compute the same.
		fmt.Sprintf("CREATE VIEW mpt_sneaky.part_mixed AS SELECT %s AS email FROM mpt_data.events_2026 e %s UNION ALL SELECT e.ip::text FROM mpt_parts.events_2027 e",
			tok("e.ip", classify.IPAddress, token.Trim), from),
		// The partitioned table itself, masked: an Append over partitions.
		fmt.Sprintf("CREATE VIEW mpt_masked.events AS SELECT b.id, %s AS ip FROM mpt_data.events b %s", tok("b.ip", classify.IPAddress, token.Trim), from),
		"GRANT SELECT ON mpt_masked.events TO mpt_clean",
		// Prefix keeps at most 8 characters; 9 of an email is most of it.
		"CREATE VIEW mpt_sneaky.long_prefix AS SELECT left(c.email, 9) AS email FROM mpt_data.customers c",
		// The view lists its subquery's columns in another order. The plan,
		// not the view's column list, says which output is the email.
		"CREATE VIEW mpt_sneaky.swapped WITH (security_barrier) AS SELECT v.id, v.email FROM (SELECT c.email, c.id FROM mpt_data.customers c OFFSET 0) v",
		// pg_authid holds password hashes; PUBLIC cannot read it, the owner can.
		"CREATE VIEW mpt_sneaky.authid AS SELECT rolpassword AS email FROM pg_authid",
		// What PUBLIC can read in the catalog anyway: no finding.
		"CREATE VIEW mpt_fn.relnames AS SELECT c.relname, n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
		"GRANT SELECT ON mpt_fn.relnames TO mpt_clean",
		"GRANT USAGE ON SCHEMA mpt_sneaky TO mpt_sneaky",
		"GRANT SELECT ON ALL TABLES IN SCHEMA mpt_sneaky TO mpt_sneaky",
		"REVOKE SELECT ON mpt_sneaky.key_material FROM mpt_sneaky",
		"ALTER TABLE mpt_data.accounts OWNER TO mpt_owner",
		"CREATE FUNCTION mpt_fn.customer_email(int) RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT email FROM mpt_data.customers WHERE id = $1'",
		"REVOKE EXECUTE ON FUNCTION mpt_fn.customer_email(int) FROM PUBLIC",
		// SECURITY INVOKER, executable by everyone: not a path.
		"CREATE FUNCTION mpt_fn.invoker_email(int) RETURNS text LANGUAGE sql AS 'SELECT email FROM mpt_data.customers WHERE id = $1'",

		// One path per role.
		"GRANT USAGE ON SCHEMA mpt_data TO mpt_reader, mpt_owner, mpt_direct, mpt_table, mpt_part, mpt_matview, mpt_unlab",
		"GRANT SELECT ON mpt_data.customers TO mpt_reader, mpt_table",
		"GRANT SELECT (id, email) ON mpt_data.customers TO mpt_direct",
		"GRANT USAGE ON SCHEMA mpt_pub TO mpt_public",
		"GRANT SELECT ON mpt_pub.leads TO PUBLIC",
		"GRANT mpt_reader TO mpt_mid",
		"GRANT mpt_mid TO mpt_inherit",
		"GRANT mpt_reader TO mpt_noinherit",
		"GRANT mpt_owner TO mpt_ownmember",
		"GRANT USAGE ON SCHEMA mpt_views TO mpt_rawview, mpt_nested, mpt_joinview, mpt_expr, mpt_subquery, mpt_barrier, mpt_fakemask",
		"GRANT SELECT ON mpt_views.contacts TO mpt_rawview",
		"GRANT SELECT ON mpt_views.contacts_nested TO mpt_nested",
		"GRANT SELECT ON mpt_views.order_names TO mpt_joinview",
		"GRANT SELECT ON mpt_views.shouting TO mpt_expr",
		"GRANT SELECT ON mpt_views.order_emails TO mpt_subquery",
		"GRANT SELECT ON mpt_views.barrier TO mpt_barrier",
		"GRANT SELECT ON mpt_views.fakemask TO mpt_fakemask",
		"GRANT USAGE ON SCHEMA mpt_masked TO mpt_clean",
		"GRANT SELECT ON mpt_masked.customers TO mpt_clean",
		"GRANT USAGE ON SCHEMA mpt_fn TO mpt_secdef, mpt_clean",
		"GRANT EXECUTE ON FUNCTION mpt_fn.customer_email(int) TO mpt_secdef",
		"GRANT USAGE ON SCHEMA mpt_internal TO mpt_key, mpt_keycol",
		"GRANT SELECT ON mpt_internal.key_material TO mpt_key",
		"GRANT SELECT (ipad) ON mpt_internal.key_material TO mpt_keycol",
		"GRANT SELECT ON mpt_data.events_2026 TO mpt_part",
		"GRANT USAGE ON SCHEMA mpt_parts TO mpt_part",
		"GRANT SELECT ON mpt_parts.events_2027 TO mpt_part",
		"GRANT SELECT ON mpt_data.customer_mv TO mpt_matview",
		"GRANT SELECT ON mpt_data.unlabeled TO mpt_unlab",
		"GRANT USAGE ON SCHEMA mpt_data, mpt_views TO mpt_derived",
		"GRANT SELECT (id, email_tok) ON mpt_data.contacts TO mpt_derived",
		"GRANT SELECT ON mpt_views.contact_tokens TO mpt_derived",
		"GRANT pg_read_server_files TO mpt_srvfiles",
		"GRANT pg_read_all_stats TO mpt_stats",
		// Last, so it does not apply to the tables above.
		"ALTER DEFAULT PRIVILEGES IN SCHEMA mpt_data GRANT SELECT ON TABLES TO mpt_defpriv",
	)
	if version >= 140000 {
		exec(t, conn, "GRANT pg_read_all_data TO mpt_readall")
	}
	if version >= 160000 {
		// A grant with neither INHERIT nor SET gives nothing.
		exec(t, conn, "GRANT mpt_reader TO mpt_nouse WITH INHERIT FALSE, SET FALSE")
	}
	var fdwAvailable bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'postgres_fdw')").Scan(&fdwAvailable); err != nil {
		t.Fatal(err)
	}
	if fdwAvailable {
		exec(t, conn,
			"CREATE EXTENSION IF NOT EXISTS postgres_fdw",
			"CREATE SERVER mpt_loop FOREIGN DATA WRAPPER postgres_fdw OPTIONS (dbname 'mpt_remote')",
			"CREATE USER MAPPING FOR mpt_fdw SERVER mpt_loop",
			// Like extension functions on managed services: SECURITY DEFINER,
			// owned by an admin who reads everything, executable by PUBLIC.
			"CREATE FUNCTION mpt_fn.ext_email(int) RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT email FROM mpt_data.customers WHERE id = $1'",
			extAddMember,
			// Like PostGIS's geometry_columns: an extension's view over the
			// catalog, readable by PUBLIC.
			"CREATE VIEW mpt_fn.ext_catalog AS SELECT c.relname, a.attname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid",
			"ALTER EXTENSION postgres_fdw ADD VIEW mpt_fn.ext_catalog",
			"GRANT SELECT ON mpt_fn.ext_catalog TO PUBLIC",
		)
	}
	exec(t, conn, "ANALYZE mpt_data.customers", "ANALYZE mpt_internal.key_material")
	return fdwAvailable
}

// expect is a finding the report must contain: same status and object, and
// a path containing every fragment.
type expect struct {
	status Status
	object string
	path   []string
}

func (e expect) matches(f Finding) bool {
	if f.Status != e.status || f.Object != e.object {
		return false
	}
	for _, p := range e.path {
		if !strings.Contains(f.Path, p) {
			return false
		}
	}
	return true
}

func sneakyExpectations() []expect {
	var e []expect
	for _, v := range sneakyViews {
		e = append(e, expect{status: Unknown, object: "mpt_sneaky." + v + ".email"})
	}
	return e
}

func runReport(t *testing.T, conn *pgx.Conn, role string) *Report {
	t.Helper()
	r, err := Postgres(context.Background(), conn, role, testClassification(), Options{Schemas: testSchemas, InternalSchema: testInternal})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func dump(r *Report) string {
	var b bytes.Buffer
	r.WriteText(&b)
	return b.String()
}

func TestReportPostgres(t *testing.T) {
	conn, version := pgTestConn(t)
	fdw := fixture(t, conn, version)

	const email, name, phone = "mpt_data.customers.email", "mpt_data.customers.name", "mpt_data.customers.phone"
	createRole := expect{Warn, "role", []string{"CREATEROLE on mpt_createrole"}}
	if version < 160000 {
		createRole.status = Unknown
	}
	cases := []struct {
		role    string
		minVer  int
		needFDW bool
		want    []expect
		// mustNot lists objects that must not appear as RAW, UNKNOWN or KEY.
		mustNot []string
		pass    bool
	}{
		{role: "mpt_direct", want: []expect{{Raw, email, []string{"SELECT on column granted to mpt_direct"}}}, mustNot: []string{name, phone}},
		{role: "mpt_table", want: []expect{
			{Raw, email, []string{"SELECT granted to mpt_table"}},
			{Raw, name, nil}, {Raw, phone, nil},
		}},
		{role: "mpt_public", want: []expect{{Raw, "mpt_pub.leads.email", []string{"PUBLIC"}}}, mustNot: []string{email}},
		{role: "mpt_inherit", want: []expect{{Raw, email, []string{"inherited: mpt_inherit > mpt_mid > mpt_reader"}}}},
		{role: "mpt_noinherit", want: []expect{{Raw, email, []string{"by SET ROLE: mpt_noinherit > mpt_reader"}}}},
		{role: "mpt_nouse", minVer: 160000, mustNot: []string{email, name, phone}, pass: true},
		{role: "mpt_ownmember", want: []expect{{Raw, "mpt_data.accounts.iban", []string{"owner mpt_owner (inherited"}}}, mustNot: []string{email}},
		{role: "mpt_super", want: []expect{
			{Raw, email, []string{"superuser mpt_super"}},
			{Raw, "mpt_data.accounts.iban", nil},
			{Key, testInternal + ".key_material", nil},
		}},
		{role: "mpt_readall", minVer: 140000, want: []expect{
			{Raw, email, []string{"pg_read_all_data"}},
			{Raw, "mpt_pub.leads.email", nil},
			{Key, testInternal + ".key_material", nil},
		}},
		{role: "mpt_rawview", want: []expect{{Raw, "mpt_views.contacts.email", []string{"passes through " + email}}}, mustNot: []string{email}},
		{role: "mpt_nested", want: []expect{{Raw, "mpt_views.contacts_nested.email", []string{"passes through " + email}}}},
		{role: "mpt_joinview", want: []expect{{Raw, "mpt_views.order_names.customer", []string{"passes through " + name}}}},
		{role: "mpt_expr", want: []expect{{Unknown, "mpt_views.shouting.email", []string{"not a maskplan transform"}}}},
		{role: "mpt_subquery", want: []expect{{Unknown, "mpt_views.order_emails.email", []string{"cannot trace"}}}},
		{role: "mpt_barrier", want: []expect{{Raw, "mpt_views.barrier.email", []string{"passes through mpt_data.customers.email"}}}},
		{role: "mpt_fakemask", want: []expect{{Unknown, "mpt_views.fakemask.email", []string{"not a maskplan transform"}}}},
		{role: "mpt_clean", want: []expect{
			{Masked, "mpt_masked.customers.email", []string{"maskplan token of " + email}},
			{Masked, "mpt_masked.customers.phone", []string{"maskplan token of " + phone}},
			{Masked, "mpt_masked.customers.fake_email", []string{"maskplan fake_name of " + email}},
			{Masked, "mpt_masked.customers.phone_prefix", []string{"maskplan prefix of " + phone}},
			{Masked, "mpt_masked.events.ip", []string{"maskplan token of mpt_data.events.ip"}},
		}, mustNot: []string{email, phone, "mpt_masked.customers.id", "view mpt_masked.big_orders", "mpt_masked.events.id"}, pass: true},
		{role: "mpt_sneaky", want: append(sneakyExpectations(),
			expect{Raw, "mpt_sneaky.swapped.email", []string{"passes through " + email}},
			expect{Unlabeled, "mpt_sneaky.fake_other_column.email", nil},
			expect{Unknown, "view mpt_sneaky.cast_error", []string{"reads " + email + " raw for every row"}}), mustNot: []string{email}},
		// An extension's definer function warns but does not fail a clean role.
		{role: "mpt_clean", needFDW: true, want: []expect{
			{Warn, "function mpt_fn.ext_email(integer)", []string{"from extension postgres_fdw", "executable by mpt_clean"}},
			{Warn, "view mpt_fn.ext_catalog", []string{"from extension postgres_fdw"}},
		}, pass: true},
		// A materialized token column is not masked until what fills it is verified.
		{role: "mpt_derived", want: []expect{
			{Unknown, "mpt_data.contacts.email_tok", []string{"token column of email", "not verified"}},
			{Unknown, "mpt_views.contact_tokens.email_tok", []string{"passes through mpt_data.contacts.email_tok", "not verified"}},
		}, mustNot: []string{"mpt_data.contacts.email"}},
		{role: "mpt_secdef", want: []expect{{Unknown, "function mpt_fn.customer_email(integer)", []string{"SECURITY DEFINER", "executable by mpt_secdef"}}}},
		{role: "mpt_defpriv", want: []expect{{Warn, "default privileges in schema mpt_data", []string{"readable by mpt_defpriv"}}}, pass: true},
		{role: "mpt_fdw", needFDW: true, want: []expect{{Unknown, "foreign server mpt_loop", []string{"user mapping for mpt_fdw"}}}},
		{role: "mpt_key", want: []expect{{Key, testInternal + ".key_material", []string{"as mpt_key"}}}},
		{role: "mpt_keycol", want: []expect{{Key, testInternal + ".key_material", []string{"as mpt_keycol"}}}},
		{role: "mpt_part", want: []expect{{Raw, "mpt_data.events_2026.ip", nil}, {Raw, "mpt_parts.events_2027.ip", nil}}, mustNot: []string{"mpt_data.events.ip"}},
		{role: "mpt_matview", want: []expect{{Raw, "mpt_data.customer_mv.email", nil}}, mustNot: []string{email}},
		{role: "mpt_unlab", want: []expect{
			{Unlabeled, "mpt_data.unlabeled.secret_notes", []string{"not in the classification"}},
			{Unlabeled, "mpt_data.unlabeled.id", nil},
		}},
		{role: "mpt_createrole", want: []expect{createRole}, pass: version >= 160000},
		{role: "mpt_srvfiles", want: []expect{{Unknown, "role", []string{"pg_read_server_files"}}}},
		{role: "mpt_repl", want: []expect{{Unknown, "role", []string{"REPLICATION on mpt_repl"}}}},
		{role: "mpt_stats", want: []expect{{Warn, "role", []string{"pg_read_all_stats", "query text"}}}, pass: true},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			if version < c.minVer {
				t.Skipf("needs server_version_num >= %d", c.minVer)
			}
			if c.needFDW && !fdw {
				t.Skip("postgres_fdw not available")
			}
			r := runReport(t, conn, c.role)
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
				// The one unacceptable failure: MASKED for anything that is not
				// a real maskplan token view.
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

	t.Run("clean role really cannot read raw", func(t *testing.T) {
		ctx := context.Background()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE mpt_clean"); err != nil {
			t.Fatal(err)
		}
		var tokEmail string
		if err := tx.QueryRow(ctx, "SELECT email FROM mpt_masked.customers WHERE id = 1").Scan(&tokEmail); err != nil {
			t.Fatal(err)
		}
		v := "alice@example.com"
		if want := *token.Token(testKey, classify.Email, token.Email, &v); tokEmail != want {
			t.Errorf("masked view returned %q, want %q", tokEmail, want)
		}
		if _, err := tx.Exec(ctx, "SELECT email FROM mpt_data.customers"); err == nil {
			t.Error("mpt_clean read mpt_data.customers directly")
		}
	})

	// A key written into a view definition is readable by every role
	// through pg_views, so it fails even the clean role.
	t.Run("key literal in a view", func(t *testing.T) {
		ipad, opad := token.Pads(testKey)
		tk, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{Expr: "c.email", Label: classify.Email, Normalizer: token.Email},
			sqlexpr.Pads{IPad: fmt.Sprintf(`'\x%x'::bytea`, ipad), OPad: fmt.Sprintf(`'\x%x'::bytea`, opad)})
		if err != nil {
			t.Fatal(err)
		}
		// The same key in dollar quotes, which a quote-pairing regular
		// expression reads wrong.
		dollar, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{Expr: "c.email", Label: classify.Email, Normalizer: token.Email},
			sqlexpr.Pads{IPad: fmt.Sprintf(`$k$\x%x$k$::bytea`, ipad), OPad: fmt.Sprintf(`$$\x%x$$::bytea`, opad)})
		if err != nil {
			t.Fatal(err)
		}
		exec(t, conn, "CREATE VIEW mpt_sneaky.literal_key AS SELECT "+tk+" AS email FROM mpt_data.customers c",
			"CREATE VIEW mpt_sneaky.literal_key_dollar AS SELECT "+dollar+" AS email FROM mpt_data.customers c",
			"GRANT SELECT ON mpt_sneaky.literal_key, mpt_sneaky.literal_key_dollar TO mpt_sneaky")
		defer exec(t, conn, "DROP VIEW mpt_sneaky.literal_key, mpt_sneaky.literal_key_dollar")
		for _, c := range []struct {
			role string
			show bool
			want []expect
		}{
			{"mpt_clean", false, []expect{{Key, "view mpt_sneaky.literal_key", []string{"definition contains the token key material"}},
				{Key, "view mpt_sneaky.literal_key_dollar", []string{"definition contains the token key material"}}}},
			{"mpt_sneaky", false, []expect{{Unknown, "mpt_sneaky.literal_key.email", []string{"not a maskplan transform: " + hiddenExpr}},
				{Unknown, "mpt_sneaky.literal_key_dollar.email", []string{"not a maskplan transform: " + hiddenExpr}}}},
			{"mpt_sneaky", true, []expect{{Unknown, "mpt_sneaky.literal_key.email", []string{"not a maskplan transform: ('tok_'"}},
				{Unknown, "mpt_sneaky.literal_key_dollar.email", []string{"not a maskplan transform: ('tok_'"}}}},
		} {
			r, err := Postgres(context.Background(), conn, c.role, testClassification(), Options{Schemas: testSchemas, InternalSchema: testInternal, ShowExpressions: c.show})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range r.Findings {
				noSecrets(t, f)
			}
			for _, e := range c.want {
				found := false
				for _, f := range r.Findings {
					found = found || e.matches(f)
				}
				if !found {
					t.Errorf("%s: missing %s %s\n%s", c.role, e.status, e.object, dump(r))
				}
			}
			if !r.Failed() {
				t.Errorf("%s passed with the key in a view definition", c.role)
			}
		}
	})

	t.Run("as-role", func(t *testing.T) {
		var version int
		if err := conn.QueryRow(context.Background(), "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version < 150000 {
			t.Skip("security_invoker views are PostgreSQL 15 and later")
		}
		// SELECT on the view, nothing on the table: the role cannot read
		// through it. Planned as the inspector, it looks raw.
		exec(t, conn, "CREATE VIEW mpt_masked.invoker_contacts WITH (security_invoker = true) AS SELECT id, email FROM mpt_data.customers",
			"GRANT SELECT ON mpt_masked.invoker_contacts TO mpt_clean")
		defer exec(t, conn, "DROP VIEW mpt_masked.invoker_contacts")
		as := func(asRole bool) *Report {
			r, err := Postgres(context.Background(), conn, "mpt_clean", testClassification(), Options{Schemas: testSchemas, InternalSchema: testInternal, AsRole: asRole})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		find := func(r *Report, obj string) *Finding {
			for i := range r.Findings {
				if r.Findings[i].Object == obj {
					return &r.Findings[i]
				}
			}
			return nil
		}
		if f := find(as(false), "mpt_masked.invoker_contacts.email"); f == nil || f.Status != Raw {
			t.Errorf("as the inspector: %+v, want RAW (over-reported)", f)
		}
		r := as(true)
		if f := find(r, "mpt_masked.invoker_contacts.email"); f == nil || f.Status != Warn || !strings.Contains(f.Path, "denied") {
			t.Errorf("as the role: %+v, want WARN", f)
		}
		if f := find(r, "mpt_masked.customers.email"); f == nil || f.Status != Masked || r.Failed() {
			t.Errorf("as the role, the masked view: %+v, failed %v\n%s", f, r.Failed(), dump(r))
		}
		// A definer view still passes raw data through, whoever plans it.
		r, err := Postgres(context.Background(), conn, "mpt_rawview", testClassification(), Options{Schemas: testSchemas, InternalSchema: testInternal, AsRole: true})
		if err != nil {
			t.Fatal(err)
		}
		if f := find(r, "mpt_views.contacts.email"); f == nil || f.Status != Raw {
			t.Errorf("as mpt_rawview: %+v, want RAW", f)
		}
	})

	t.Run("canonicalization never makes a perturbed token equal", func(t *testing.T) { canonicalAdversarial(t, conn) })

	// pg_stat_statements turns on compute_query_id, which adds a query
	// identifier to EXPLAIN VERBOSE; the plan comparison must ignore it.
	t.Run("compute_query_id on", func(t *testing.T) {
		if version < 140000 {
			t.Skip("compute_query_id is PostgreSQL 14 and later")
		}
		exec(t, conn, "SET compute_query_id = on")
		defer exec(t, conn, "RESET compute_query_id")
		r := runReport(t, conn, "mpt_clean")
		masked := 0
		for _, f := range r.Findings {
			if f.Status == Masked {
				masked++
			}
		}
		if masked != 5 || r.Failed() {
			t.Errorf("with compute_query_id on: %d masked, failed %v\n%s", masked, r.Failed(), dump(r))
		}
	})

	// Mutations: give the clean role one more path each, and the report
	// must fail it.
	mutations := []struct {
		name          string
		apply, revert []string
		needFDW       bool
	}{
		{"inherit a reader", []string{"GRANT mpt_reader TO mpt_clean"}, []string{"REVOKE mpt_reader FROM mpt_clean"}, false},
		{"security_barrier view", []string{"GRANT USAGE ON SCHEMA mpt_views TO mpt_clean", "GRANT SELECT ON mpt_views.barrier TO mpt_clean"},
			[]string{"REVOKE SELECT ON mpt_views.barrier FROM mpt_clean", "REVOKE USAGE ON SCHEMA mpt_views FROM mpt_clean"}, false},
		{"key table", []string{"GRANT USAGE ON SCHEMA mpt_internal TO mpt_clean", "GRANT SELECT (opad) ON mpt_internal.key_material TO mpt_clean"},
			[]string{"REVOKE SELECT (opad) ON mpt_internal.key_material FROM mpt_clean", "REVOKE USAGE ON SCHEMA mpt_internal FROM mpt_clean"}, false},
		{"security definer function", []string{"GRANT EXECUTE ON FUNCTION mpt_fn.customer_email(int) TO mpt_clean"},
			[]string{"REVOKE EXECUTE ON FUNCTION mpt_fn.customer_email(int) FROM mpt_clean"}, false},
		{"schema with a PUBLIC table", []string{"GRANT USAGE ON SCHEMA mpt_pub TO mpt_clean"}, []string{"REVOKE USAGE ON SCHEMA mpt_pub FROM mpt_clean"}, false},
		{"public user mapping", []string{"CREATE USER MAPPING FOR PUBLIC SERVER mpt_loop"}, []string{"DROP USER MAPPING FOR PUBLIC SERVER mpt_loop"}, true},
		{"superuser", []string{"ALTER ROLE mpt_clean SUPERUSER"}, []string{"ALTER ROLE mpt_clean NOSUPERUSER"}, false},
		{"server files", []string{"GRANT pg_read_server_files TO mpt_clean"}, []string{"REVOKE pg_read_server_files FROM mpt_clean"}, false},
		{"replication", []string{"ALTER ROLE mpt_clean REPLICATION"}, []string{"ALTER ROLE mpt_clean NOREPLICATION"}, false},
		{"definer function leaves its extension", []string{extDropMember}, []string{extAddMember}, true},
		{"column of a raw table", []string{"GRANT USAGE ON SCHEMA mpt_data TO mpt_clean", "GRANT SELECT (phone) ON mpt_data.customers TO mpt_clean"},
			[]string{"REVOKE SELECT (phone) ON mpt_data.customers FROM mpt_clean", "REVOKE USAGE ON SCHEMA mpt_data FROM mpt_clean"}, false},
	}
	for _, m := range mutations {
		t.Run("mutation/"+m.name, func(t *testing.T) {
			if m.needFDW && !fdw {
				t.Skip("postgres_fdw not available")
			}
			exec(t, conn, m.apply...)
			defer exec(t, conn, m.revert...)
			if r := runReport(t, conn, "mpt_clean"); !r.Failed() {
				t.Errorf("report passed mpt_clean after: %s\n%s", strings.Join(m.apply, "; "), dump(r))
			}
		})
	}
	t.Run("clean again after mutations", func(t *testing.T) {
		if r := runReport(t, conn, "mpt_clean"); r.Failed() {
			t.Errorf("mutations were not reverted:\n%s", dump(r))
		}
	})
}
