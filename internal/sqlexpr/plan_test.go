package sqlexpr

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chauhanprateek89/maskplan/internal/token"
)

// These tests pin down planner behavior that masking depends on for safety
// and speed. They create and drop their own schema, maskplan_test_plan.

const planSchema = "maskplan_test_plan"

var planKey = []byte("plan-test-key-0123456789abcdef!!")

// maskedViewSQL builds a masked view the way the compiler will: tokens from
// sqlexpr.Token, the key table read through sqlexpr.KeySource.
func maskedViewSQL(t *testing.T, e Engine, name, base, cols, options string, tokens ...Column) string {
	t.Helper()
	from, pads, err := KeySource(e, planSchema+".key_material", "k")
	if err != nil {
		t.Fatal(err)
	}
	exprs := []string{cols}
	for _, c := range tokens {
		expr, err := Token(e, c, pads)
		if err != nil {
			t.Fatal(err)
		}
		alias := c.Expr[strings.LastIndex(c.Expr, ".")+1:]
		exprs = append(exprs, expr+" AS "+alias)
	}
	return fmt.Sprintf("CREATE VIEW %s.%s%s AS SELECT %s FROM %s %s", planSchema, name, options, strings.Join(exprs, ", "), base, from)
}

func emailToken(expr string) Column {
	return Column{Expr: expr, Label: "user.contact.email", Normalizer: token.Email}
}

// --- Postgres -------------------------------------------------------------

func pgConn(t *testing.T) (*pgx.Conn, *[]string) {
	t.Helper()
	dsn := os.Getenv(setups[Postgres].envDSN)
	if dsn == "" {
		t.Skipf("%s not set", setups[Postgres].envDSN)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	notices := &[]string{}
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		mu.Lock()
		*notices = append(*notices, n.Message)
		mu.Unlock()
	}
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+planSchema+" CASCADE")
		conn.Close(context.Background())
	})
	return conn, notices
}

func pgExec(t *testing.T, conn *pgx.Conn, qs ...string) {
	t.Helper()
	for _, q := range qs {
		if _, err := conn.Exec(context.Background(), q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
}

func pgSetup(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ipad, opad := token.Pads(planKey)
	pgExec(t, conn,
		"DROP SCHEMA IF EXISTS "+planSchema+" CASCADE",
		"CREATE SCHEMA "+planSchema,
		"CREATE TABLE "+planSchema+".key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad bytea NOT NULL, opad bytea NOT NULL)",
		"CREATE TABLE "+planSchema+".users (id int PRIMARY KEY, email text, country text)",
		"INSERT INTO "+planSchema+".users SELECT g, 'raw' || g || '@example.com', CASE WHEN g % 2 = 0 THEN 'IE' ELSE 'GB' END FROM generate_series(1, 2000) g",
		"CREATE TABLE "+planSchema+".orders (id int PRIMARY KEY, customer_email text)",
		"INSERT INTO "+planSchema+".orders SELECT g, 'raw' || g || '@example.com' FROM generate_series(1, 200) g",
	)
	if _, err := conn.Exec(context.Background(), "INSERT INTO "+planSchema+".key_material VALUES (1, $1, $2)", ipad, opad); err != nil {
		t.Fatal(err)
	}
	pgExec(t, conn,
		"ANALYZE "+planSchema+".key_material",
		"ANALYZE "+planSchema+".users",
		"ANALYZE "+planSchema+".orders",
		maskedViewSQL(t, Postgres, "v_users", planSchema+".users u", "u.id, u.country", "", emailToken("u.email")),
		maskedViewSQL(t, Postgres, "v_orders", planSchema+".orders o", "o.id", "", emailToken("o.customer_email")),
		// Row-filtered views keep security_barrier.
		maskedViewSQL(t, Postgres, "v_users_ie", planSchema+".users u", "u.id, u.country", " WITH (security_barrier)", emailToken("u.email"))+" WHERE u.country = 'IE'",
		// A leaky function, as an agent could write one: it reports every
		// argument it sees, and is cheap so the planner evaluates it early.
		`CREATE FUNCTION `+planSchema+`.leak(text) RETURNS boolean LANGUAGE plpgsql COST 0.0000001 AS $$
		 BEGIN RAISE NOTICE 'leak:%', $1; RETURN true; END $$`,
	)
}

// A leaky function in the agent's WHERE clause on a column-only view (no
// security_barrier) must only ever see tokens, never a raw masked value.
func TestLeakyFunctionPostgres(t *testing.T) {
	conn, notices := pgConn(t)
	pgSetup(t, conn)
	queries := []string{
		"SELECT count(*) FROM " + planSchema + ".v_users WHERE " + planSchema + ".leak(email)",
		"SELECT id FROM " + planSchema + ".v_users WHERE " + planSchema + ".leak(email) AND id < 10",
		"SELECT id FROM " + planSchema + ".v_users WHERE id = 5 OR " + planSchema + ".leak(email)",
		"SELECT count(*) FROM " + planSchema + ".v_users u JOIN " + planSchema + ".v_orders o ON u.email = o.customer_email WHERE " + planSchema + ".leak(o.customer_email)",
	}
	for _, q := range queries {
		*notices = nil
		rows, err := conn.Query(context.Background(), q)
		if err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
		rows.Close()
		seen := 0
		for _, n := range *notices {
			v, ok := strings.CutPrefix(n, "leak:")
			if !ok {
				continue
			}
			seen++
			if !strings.HasPrefix(v, token.Prefix) || strings.Contains(v, "@") {
				t.Fatalf("leaky function saw a raw value %q in: %s", v, q)
			}
		}
		if seen == 0 {
			t.Fatalf("leaky function never ran, so the test proves nothing: %s", q)
		}
	}
}

// A row-filtered view keeps security_barrier: a leaky function must not see
// rows the view's own filter removes.
func TestLeakyFunctionRowFilterPostgres(t *testing.T) {
	conn, notices := pgConn(t)
	pgSetup(t, conn)
	*notices = nil
	q := "SELECT count(*) FROM " + planSchema + ".v_users_ie WHERE " + planSchema + ".leak(country)"
	rows, err := conn.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	seen := 0
	for _, n := range *notices {
		if v, ok := strings.CutPrefix(n, "leak:"); ok {
			seen++
			if v != "IE" {
				t.Fatalf("leaky function saw a filtered-out row (country %q)", v)
			}
		}
	}
	if seen == 0 {
		t.Fatal("leaky function never ran")
	}
}

type pgPlanNode struct {
	NodeType           string       `json:"Node Type"`
	PartialMode        string       `json:"Partial Mode"`
	ParallelAware      bool         `json:"Parallel Aware"`
	RelationName       string       `json:"Relation Name"`
	ParentRelationship string       `json:"Parent Relationship"`
	SubplanName        string       `json:"Subplan Name"`
	Plans              []pgPlanNode `json:"Plans"`
}

func (n pgPlanNode) walk(f func(pgPlanNode)) {
	f(n)
	for _, c := range n.Plans {
		c.walk(f)
	}
}

func pgExplain(t *testing.T, conn *pgx.Conn, q string) pgPlanNode {
	t.Helper()
	var raw []byte
	if err := conn.QueryRow(context.Background(), "EXPLAIN (FORMAT JSON) "+q).Scan(&raw); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
	var out []struct {
		Plan pgPlanNode `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 1 {
		t.Fatalf("cannot parse plan: %v\n%s", err, raw)
	}
	return out[0].Plan
}

// The masked full scan must stay fully parallel: the pads come from InitPlans,
// the key table is never the outer side of a nested loop, and the aggregate is
// split into a partial aggregate below the Gather. Without that split (which
// security_barrier prevents) every row is shipped through the Gather and, at
// real parallel costs, the planner falls back to a serial plan. Parallel costs
// are zeroed so the planner picks a parallel plan whenever the query allows
// one, even on a small test table.
func TestPlanPostgres(t *testing.T) {
	conn, _ := pgConn(t)
	pgSetup(t, conn)
	pgExec(t, conn,
		"SET parallel_setup_cost = 0",
		"SET parallel_tuple_cost = 0",
		"SET min_parallel_table_scan_size = 0",
		"SET max_parallel_workers_per_gather = 2",
	)
	plan := pgExplain(t, conn, "SELECT max(email) FROM "+planSchema+".v_users")
	var gather, parallelScan, partialAgg, initPlan bool
	plan.walk(func(n pgPlanNode) {
		switch {
		case strings.HasPrefix(n.NodeType, "Gather"):
			gather = true
			n.walk(func(c pgPlanNode) {
				if c.NodeType == "Aggregate" && c.PartialMode == "Partial" {
					partialAgg = true
				}
			})
		case n.NodeType == "Seq Scan" && n.ParallelAware && n.RelationName == "users":
			parallelScan = true
		case n.NodeType == "Nested Loop" && len(n.Plans) > 0 && n.Plans[0].RelationName == "key_material":
			t.Errorf("key_material is the outer side of a nested loop")
		}
		if strings.HasPrefix(n.SubplanName, "InitPlan") || n.ParentRelationship == "InitPlan" {
			initPlan = true
		}
	})
	if !gather || !parallelScan {
		t.Errorf("masked scan is not parallel (gather=%v, parallel seq scan on users=%v)", gather, parallelScan)
	}
	if !partialAgg {
		t.Error("no partial aggregate below the Gather: every row would cross the Gather")
	}
	if !initPlan {
		t.Error("pads are not read through an InitPlan")
	}
}

// --- MySQL ----------------------------------------------------------------

func mysqlSetup(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(setups[MySQL].envDSN)
	if dsn == "" {
		t.Skipf("%s not set", setups[MySQL].envDSN)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		db.Exec("DROP DATABASE IF EXISTS " + planSchema)
		db.Close()
	})
	ipad, opad := token.Pads(planKey)
	seq := "WITH RECURSIVE seq (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < %d) "
	for _, q := range []string{
		"SET SESSION cte_max_recursion_depth = 5000",
		"DROP DATABASE IF EXISTS " + planSchema,
		"CREATE DATABASE " + planSchema + " CHARACTER SET utf8mb4",
		"CREATE TABLE " + planSchema + ".key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad VARBINARY(64) NOT NULL, opad VARBINARY(64) NOT NULL)",
		"CREATE TABLE " + planSchema + ".users (id INT PRIMARY KEY, email VARCHAR(255))",
		"INSERT INTO " + planSchema + ".users " + fmt.Sprintf(seq, 2000) + "SELECT n, CONCAT('raw', n, '@example.com') FROM seq",
		"CREATE TABLE " + planSchema + ".orders (id INT PRIMARY KEY, customer_email VARCHAR(255))",
		"INSERT INTO " + planSchema + ".orders " + fmt.Sprintf(seq, 200) + "SELECT n, CONCAT('raw', n, '@example.com') FROM seq",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	if _, err := db.Exec("INSERT INTO "+planSchema+".key_material VALUES (1, ?, ?)", ipad, opad); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"ANALYZE TABLE " + planSchema + ".key_material, " + planSchema + ".users, " + planSchema + ".orders",
		maskedViewSQL(t, MySQL, "v_users", planSchema+".users u", "u.id", "", emailToken("u.email")),
		maskedViewSQL(t, MySQL, "v_orders", planSchema+".orders o", "o.id", "", emailToken("o.customer_email")),
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	return db
}

// findTables collects every "table" object in MySQL's JSON plan.
func findTables(v any, out *[]map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		if tbl, ok := x["table"].(map[string]any); ok {
			*out = append(*out, tbl)
		}
		for _, c := range x {
			findTables(c, out)
		}
	case []any:
		for _, c := range x {
			findTables(c, out)
		}
	}
}

// The key table must be a const table, so views stay mergeable, and two
// masked views must hash-join on a token instead of nesting loops.
func TestPlanMySQL(t *testing.T) {
	db := mysqlSetup(t)
	// MySQL 9 defaults to EXPLAIN JSON version 2; this test reads version 1.
	// db is limited to one connection, so the setting sticks.
	if _, err := db.Exec("SET SESSION explain_json_format_version = 1"); err != nil && !strings.Contains(err.Error(), "1193") {
		t.Fatal(err)
	}

	var raw string
	if err := db.QueryRow("EXPLAIN FORMAT=JSON SELECT max(email) FROM " + planSchema + ".v_users").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plan any
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		t.Fatal(err)
	}
	var tables []map[string]any
	findTables(plan, &tables)
	found := false
	for _, tbl := range tables {
		if tbl["table_name"] == "k" || tbl["table_name"] == "key_material" {
			found = true
			if tbl["access_type"] != "const" && tbl["access_type"] != "system" {
				t.Errorf("key_material access_type = %v, want const", tbl["access_type"])
			}
		}
		if tbl["materialized_from_subquery"] != nil {
			t.Errorf("view was materialized instead of merged: %v", tbl["table_name"])
		}
	}
	if !found {
		t.Errorf("key_material not found in plan:\n%s", raw)
	}

	var tree string
	q := "EXPLAIN FORMAT=TREE SELECT count(*) FROM " + planSchema + ".v_users u JOIN " + planSchema + ".v_orders o ON u.email = o.customer_email"
	if err := db.QueryRow(q).Scan(&tree); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(tree), "hash join") {
		t.Errorf("token join is not a hash join:\n%s", tree)
	}
}

// With the key table empty every token is NULL and no error is raised. This
// fails safe (no raw data, joins match nothing) but is invisible, so apply
// must assert exactly one key row and report must verify it. These tests pin
// the behavior so a change to it is noticed.
func TestEmptyKeyTablePostgres(t *testing.T) {
	conn, _ := pgConn(t)
	pgSetup(t, conn)
	pgExec(t, conn, "DELETE FROM "+planSchema+".key_material")
	var n, nulls int
	q := "SELECT count(*), count(*) FILTER (WHERE email IS NULL) FROM " + planSchema + ".v_users"
	if err := conn.QueryRow(context.Background(), q).Scan(&n, &nulls); err != nil {
		t.Fatal(err)
	}
	if n == 0 || nulls != n {
		t.Fatalf("empty key table: %d rows, %d NULL tokens; want all rows with NULL tokens", n, nulls)
	}
}

func TestEmptyKeyTableMySQL(t *testing.T) {
	db := mysqlSetup(t)
	if _, err := db.Exec("DELETE FROM " + planSchema + ".key_material"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + planSchema + ".v_users").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty key table: view returned %d rows; want 0 (inner join to the key table)", n)
	}
}
