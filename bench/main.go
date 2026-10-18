// Command bench measures the cost of maskplan tokens on Postgres and MySQL.
//
// It seeds a users table (default 10 million rows) and an orders table,
// creates masked views with the same SQL the compiler generates, and times
// three queries against both the base tables and the masked views:
//
//  1. full scan: max() over the tokenized email and phone columns
//  2. lookup:    1,000 rows by primary key
//  3. join:      users joined to orders on the email token
//
// See bench/README.md for how to run it and how to read the verdicts.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	mrand "math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// Gates agreed in the week-1 review. A masked full scan passes when both hold
// on the target service:
//   - added CPU per row per tokenized column is at most cpuBudget, measured
//     with one process so parallel workers do not hide the cost;
//   - the masked scan is within floorRatioMax of a scan that only calls md5()
//     on each column, an environment sanity check.
//
// The design-v3 gate (within 3x of the unmasked scan) is reported for
// reference; no per-row hash, md5() included, can meet it. Point lookups
// must finish under lookupBudget.
const (
	cpuBudget     = 5 * time.Microsecond
	floorRatioMax = 4.0
	lookupBudget  = 100 * time.Millisecond
)

var (
	engine    = flag.String("engine", "", "postgres or mysql")
	dsn       = flag.String("dsn", "", "connection string (pgx URL or go-sql-driver DSN)")
	rows      = flag.Int("rows", 10_000_000, "rows in the users table")
	orders    = flag.Int("orders", 0, "rows in the orders table (default rows/10)")
	runs      = flag.Int("runs", 3, "timed runs per query; the median is reported")
	lookupN   = flag.Int("lookup", 1000, "primary keys fetched by the lookup query")
	skipSeed  = flag.Bool("skip-seed", false, "reuse tables from a previous run with the same -rows and -orders")
	cleanup   = flag.Bool("cleanup", false, "drop the benchmark schemas and exit")
	jsonOut   = flag.String("json", "", "also write results as JSON to this file")
	memBudget = flag.String("join-mem", "256MB", "session memory for hash joins (work_mem / join_buffer_size), same for both sides")
)

const (
	benchSchema    = "maskplan_bench"
	internalSchema = "maskplan_internal"
)

type result struct {
	Query    string        `json:"query"`
	Unmasked time.Duration `json:"unmasked_ns"`
	// Floor is the same query hashing each column once with the engine's
	// built-in md5(): the cheapest per-row hash SQL offers. Zero if unused.
	Floor      time.Duration `json:"md5_floor_ns,omitempty"`
	Masked     time.Duration `json:"masked_ns"`
	Ratio      float64       `json:"ratio"`
	FloorRatio float64       `json:"md5_floor_ratio,omitempty"`
	// PerRowCol is the added wall-clock cost per row per tokenized column.
	PerRowCol time.Duration `json:"overhead_per_row_column_ns,omitempty"`
	// CPUPerRowCol is the same cost measured with one process (Postgres
	// parallel workers disabled; MySQL is single-threaded anyway).
	CPUPerRowCol time.Duration `json:"cpu_per_row_column_ns,omitempty"`
	Verdict      string        `json:"verdict"`
}

type report struct {
	Engine  string    `json:"engine"`
	Version string    `json:"version"`
	Rows    int       `json:"rows"`
	Orders  int       `json:"orders"`
	Runs    int       `json:"runs"`
	When    time.Time `json:"when"`
	Results []result  `json:"results"`
}

func main() {
	log.SetFlags(log.Ltime)
	flag.Parse()
	e := sqlexpr.Engine(*engine)
	if (e != sqlexpr.Postgres && e != sqlexpr.MySQL) || *dsn == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *orders == 0 {
		*orders = max(*rows/10, 1)
	}
	driver := map[sqlexpr.Engine]string{sqlexpr.Postgres: "pgx", sqlexpr.MySQL: "mysql"}[e]
	db, err := sql.Open(driver, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// Session settings must apply to every statement, so use one connection.
	db.SetMaxOpenConns(1)
	ctx := context.Background()

	if *cleanup {
		for _, s := range []string{benchSchema, internalSchema} {
			mustExec(ctx, db, dropSchema(e, s))
		}
		log.Print("dropped benchmark schemas")
		return
	}

	var version string
	must(db.QueryRowContext(ctx, "SELECT version()").Scan(&version))
	log.Printf("%s %s, users=%d orders=%d", e, version, *rows, *orders)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	if *skipSeed {
		checkSeeded(ctx, db)
	} else {
		seed(ctx, db, e)
	}
	ensureEmailIndex(ctx, db, e)
	createKeyAndViews(ctx, db, e, key)
	checkKeyRow(ctx, db)
	verify(ctx, db, e, key)

	for _, q := range sessionSettings(e) {
		mustExec(ctx, db, q)
	}

	r := report{Engine: string(e), Version: version, Rows: *rows, Orders: *orders, Runs: *runs, When: time.Now().UTC()}
	r.Results = append(r.Results, benchScan(ctx, db, e), benchLookup(ctx, db), benchFindByToken(ctx, db, key), benchJoin(ctx, db, e))
	printReport(r)
	if *jsonOut != "" {
		data, _ := json.MarshalIndent(r, "", "  ")
		must(os.WriteFile(*jsonOut, append(data, '\n'), 0o644))
	}
}

func dropSchema(e sqlexpr.Engine, s string) string {
	if e == sqlexpr.Postgres {
		return "DROP SCHEMA IF EXISTS " + s + " CASCADE"
	}
	return "DROP DATABASE IF EXISTS " + s
}

func createSchema(e sqlexpr.Engine, s string) string {
	if e == sqlexpr.Postgres {
		return "CREATE SCHEMA " + s
	}
	return "CREATE DATABASE " + s + " CHARACTER SET utf8mb4"
}

// seed creates and fills the base tables on the server. Users get mixed-case
// emails, a leading space on every tenth row, formatted phone numbers and
// some non-ASCII names; orders reference users by lowercase email, so the
// join only matches after normalization.
func seed(ctx context.Context, db *sql.DB, e sqlexpr.Engine) {
	start := time.Now()
	mustExec(ctx, db, dropSchema(e, benchSchema))
	mustExec(ctx, db, createSchema(e, benchSchema))
	n, m := *rows, *orders
	switch e {
	case sqlexpr.Postgres:
		mustExec(ctx, db, "CREATE TABLE maskplan_bench.users (id bigint PRIMARY KEY, email text, phone text, full_name text)")
		mustExec(ctx, db, "CREATE TABLE maskplan_bench.orders (id bigint PRIMARY KEY, customer_email text)")
		mustExec(ctx, db, fmt.Sprintf(`INSERT INTO maskplan_bench.users
			SELECT g,
			       CASE WHEN g %% 10 = 0 THEN ' ' ELSE '' END || 'User' || g || '@Example.com',
			       '+353 (0)1 ' || lpad(g::text, 8, '0'),
			       CASE WHEN g %% 7 = 0 THEN 'José Núñez ' ELSE 'Alex Smith ' END || g
			FROM generate_series(1::bigint, %d) g`, n))
		mustExec(ctx, db, fmt.Sprintf(`INSERT INTO maskplan_bench.orders
			SELECT g, 'user' || ((g * 7919) %% %d + 1) || '@example.com'
			FROM generate_series(1::bigint, %d) g`, n, m))
		mustExec(ctx, db, "ANALYZE maskplan_bench.users")
		mustExec(ctx, db, "ANALYZE maskplan_bench.orders")
	case sqlexpr.MySQL:
		const chunk = 1_000_000
		mustExec(ctx, db, "CREATE TABLE maskplan_bench.seq (n INT PRIMARY KEY)")
		digits := "(SELECT 0 d UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)"
		mustExec(ctx, db, fmt.Sprintf(`INSERT INTO maskplan_bench.seq
			SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d + 100000*f.d + 1
			FROM %[1]s a, %[1]s b, %[1]s c, %[1]s d, %[1]s e, %[1]s f`, digits))
		mustExec(ctx, db, "CREATE TABLE maskplan_bench.users (id BIGINT PRIMARY KEY, email VARCHAR(255), phone VARCHAR(64), full_name VARCHAR(255))")
		mustExec(ctx, db, "CREATE TABLE maskplan_bench.orders (id BIGINT PRIMARY KEY, customer_email VARCHAR(255))")
		for c := 0; c*chunk < n; c++ {
			mustExec(ctx, db, fmt.Sprintf(`INSERT INTO maskplan_bench.users
				SELECT g,
				       CONCAT(IF(g %% 10 = 0, ' ', ''), 'User', g, '@Example.com'),
				       CONCAT('+353 (0)1 ', LPAD(g, 8, '0')),
				       CONCAT(IF(g %% 7 = 0, 'José Núñez ', 'Alex Smith '), g)
				FROM (SELECT %d + n AS g FROM maskplan_bench.seq) t WHERE g <= %d`, c*chunk, n))
		}
		for c := 0; c*chunk < m; c++ {
			mustExec(ctx, db, fmt.Sprintf(`INSERT INTO maskplan_bench.orders
				SELECT g, CONCAT('user', (g * 7919) %% %d + 1, '@example.com')
				FROM (SELECT %d + n AS g FROM maskplan_bench.seq) t WHERE g <= %d`, n, c*chunk, m))
		}
		mustExec(ctx, db, "ANALYZE TABLE maskplan_bench.users, maskplan_bench.orders")
	}
	log.Printf("seeded in %s", time.Since(start).Round(time.Millisecond))
}

// checkSeeded makes -skip-seed safe: the existing tables must have exactly
// the requested sizes, or results would be reported for the wrong row count.
func checkSeeded(ctx context.Context, db *sql.DB) {
	for table, want := range map[string]int{"users": *rows, "orders": *orders} {
		var n int
		if err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s.%s", benchSchema, table)).Scan(&n); err != nil {
			log.Fatalf("-skip-seed: %v", err)
		}
		if n != want {
			log.Fatalf("-skip-seed: %s.%s has %d rows, want %d; run without -skip-seed", benchSchema, table, n, want)
		}
	}
}

// ensureEmailIndex gives the unmasked side of the find-by-email query the
// index a production table would have.
func ensureEmailIndex(ctx context.Context, db *sql.DB, e sqlexpr.Engine) {
	if e == sqlexpr.Postgres {
		mustExec(ctx, db, "CREATE INDEX IF NOT EXISTS users_email_idx ON "+benchSchema+".users (email)")
		return
	}
	var n int
	must(db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.statistics WHERE table_schema = ? AND table_name = 'users' AND index_name = 'users_email_idx'", benchSchema).Scan(&n))
	if n == 0 {
		mustExec(ctx, db, "CREATE INDEX users_email_idx ON "+benchSchema+".users (email)")
	}
}

// checkKeyRow asserts the key table holds exactly one row. With none, every
// token silently becomes NULL (Postgres) or the views return no rows (MySQL).
func checkKeyRow(ctx context.Context, db *sql.DB) {
	var n int
	must(db.QueryRowContext(ctx, "SELECT count(*) FROM "+internalSchema+".key_material").Scan(&n))
	if n != 1 {
		log.Fatalf("%s.key_material has %d rows, want exactly 1", internalSchema, n)
	}
}

var (
	emailCol = func(expr string) sqlexpr.Column {
		return sqlexpr.Column{Expr: expr, Label: "user.contact.email", Normalizer: token.Email}
	}
	phoneCol = func(expr string) sqlexpr.Column {
		return sqlexpr.Column{Expr: expr, Label: "user.contact.phone", Normalizer: token.Phone}
	}
)

func tokenExpr(e sqlexpr.Engine, c sqlexpr.Column, p sqlexpr.Pads) string {
	s, err := sqlexpr.Token(e, c, p)
	must(err)
	return s
}

func normExpr(e sqlexpr.Engine, c sqlexpr.Column) string {
	s, err := sqlexpr.Normalize(e, c)
	must(err)
	return s
}

// createKeyAndViews writes a fresh key's pads to the key table and creates
// the masked views. The key never appears in the view definitions.
func createKeyAndViews(ctx context.Context, db *sql.DB, e sqlexpr.Engine, key []byte) {
	ipad, opad := token.Pads(key)
	mustExec(ctx, db, dropSchema(e, internalSchema))
	mustExec(ctx, db, createSchema(e, internalSchema))
	// No security_barrier: these views mask columns but filter no rows, and
	// the option disables parallel workers on Postgres (see sqlexpr.KeySource).
	view := "CREATE VIEW %s.%s AS %s"
	placeholder := "$1, $2"
	binType := "bytea"
	if e == sqlexpr.MySQL {
		view = "CREATE SQL SECURITY DEFINER VIEW %s.%s AS %s"
		placeholder = "?, ?"
		binType = "VARBINARY(64)"
	}
	// One row only, so the scalar subqueries in the views are well defined.
	mustExec(ctx, db, fmt.Sprintf("CREATE TABLE %s.key_material (id smallint PRIMARY KEY CHECK (id = 1), ipad %s NOT NULL, opad %s NOT NULL)", internalSchema, binType, binType))
	mustExec(ctx, db, fmt.Sprintf("INSERT INTO %s.key_material VALUES (1, %s)", internalSchema, placeholder), ipad, opad)
	// Without statistics Postgres assumes hundreds of rows in the key table.
	if e == sqlexpr.Postgres {
		mustExec(ctx, db, "ANALYZE "+internalSchema+".key_material")
	} else {
		mustExec(ctx, db, "ANALYZE TABLE "+internalSchema+".key_material")
	}

	for _, v := range []string{"v_users", "v_orders"} {
		mustExec(ctx, db, fmt.Sprintf("DROP VIEW IF EXISTS %s.%s", benchSchema, v))
	}
	keyJoin, pads, err := sqlexpr.KeySource(e, internalSchema+".key_material", "k")
	must(err)
	users := fmt.Sprintf("SELECT u.id, %s AS email, %s AS phone FROM %s.users u %s",
		tokenExpr(e, emailCol("u.email"), pads), tokenExpr(e, phoneCol("u.phone"), pads), benchSchema, keyJoin)
	ordersSQL := fmt.Sprintf("SELECT o.id, %s AS customer_email FROM %s.orders o %s",
		tokenExpr(e, emailCol("o.customer_email"), pads), benchSchema, keyJoin)
	mustExec(ctx, db, fmt.Sprintf(view, benchSchema, "v_users", users))
	mustExec(ctx, db, fmt.Sprintf(view, benchSchema, "v_orders", ordersSQL))
}

// verify checks that the views return the tokens the Go reference computes.
func verify(ctx context.Context, db *sql.DB, e sqlexpr.Engine, key []byte) {
	for _, id := range []int{1, 10, 7, *rows} {
		var gotEmail, gotPhone, rawEmail, rawPhone string
		q := fmt.Sprintf("SELECT v.email, v.phone, u.email, u.phone FROM %[1]s.v_users v JOIN %[1]s.users u ON u.id = v.id WHERE v.id = %[2]d", benchSchema, id)
		must(db.QueryRowContext(ctx, q).Scan(&gotEmail, &gotPhone, &rawEmail, &rawPhone))
		wantEmail := *token.Token(key, "user.contact.email", token.Email, &rawEmail)
		wantPhone := *token.Token(key, "user.contact.phone", token.Phone, &rawPhone)
		if gotEmail != wantEmail || gotPhone != wantPhone {
			log.Fatalf("id %d: view tokens (%s, %s) differ from Go reference (%s, %s)", id, gotEmail, gotPhone, wantEmail, wantPhone)
		}
	}
	log.Print("view tokens match the Go reference")
}

func sessionSettings(e sqlexpr.Engine) []string {
	if e == sqlexpr.Postgres {
		return []string{fmt.Sprintf("SET work_mem = '%s'", *memBudget)}
	}
	b, err := parseBytes(*memBudget)
	must(err)
	return []string{fmt.Sprintf("SET SESSION join_buffer_size = %d", b)}
}

func parseBytes(s string) (int64, error) {
	units := map[string]int64{"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30}
	for u, mult := range units {
		if strings.HasSuffix(s, u) {
			n, err := strconv.ParseInt(strings.TrimSuffix(s, u), 10, 64)
			return n * mult, err
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func benchScan(ctx context.Context, db *sql.DB, e sqlexpr.Engine) result {
	md5 := "md5"
	if e == sqlexpr.MySQL {
		md5 = "MD5"
	}
	baseQ := fmt.Sprintf("SELECT max(email), max(phone) FROM %s.users", benchSchema)
	maskedQ := fmt.Sprintf("SELECT max(email), max(phone) FROM %s.v_users", benchSchema)
	base := timeQuery(ctx, db, "full scan, unmasked", baseQ)
	// MySQL 9 has no MD5(). Another hash would make a different floor, so
	// there the floor is not measured.
	var floor time.Duration
	hasMD5 := db.QueryRowContext(ctx, "SELECT "+md5+"('x')").Scan(new(string)) == nil
	if hasMD5 {
		floor = timeQuery(ctx, db, "full scan, md5 floor", fmt.Sprintf("SELECT max(%[1]s(email)), max(%[1]s(phone)) FROM %[2]s.users", md5, benchSchema))
	} else {
		log.Printf("full scan, md5 floor: not measured, this server has no %s()", md5)
	}
	masked := timeQuery(ctx, db, "full scan, masked", maskedQ)
	cols := time.Duration(2 * *rows)
	r := result{
		Query:    fmt.Sprintf("Full scan, %d rows, 2 tokenized columns", *rows),
		Unmasked: base, Floor: floor, Masked: masked,
		Ratio: ratio(masked, base), FloorRatio: ratio(masked, floor),
		PerRowCol:    (masked - base) / cols,
		CPUPerRowCol: (masked - base) / cols,
	}
	if e == sqlexpr.Postgres {
		mustExec(ctx, db, "SET max_parallel_workers_per_gather = 0")
		serialBase := timeQuery(ctx, db, "full scan, unmasked, 1 process", baseQ)
		serialMasked := timeQuery(ctx, db, "full scan, masked, 1 process", maskedQ)
		mustExec(ctx, db, "RESET max_parallel_workers_per_gather")
		r.CPUPerRowCol = (serialMasked - serialBase) / cols
	}
	cpuOK, floorOK := r.CPUPerRowCol <= cpuBudget, r.FloorRatio <= floorRatioMax
	gate := fmt.Sprintf("CPU %.2f µs/row/col (<= %.0f µs), %.1fx md5 floor (<= %.0fx)",
		us(r.CPUPerRowCol), us(cpuBudget), r.FloorRatio, floorRatioMax)
	if !hasMD5 {
		r.FloorRatio, floorOK = 0, true
		gate = fmt.Sprintf("CPU %.2f µs/row/col (<= %.0f µs), md5 floor not measured (no md5() on this server)", us(r.CPUPerRowCol), us(cpuBudget))
	}
	if cpuOK && floorOK {
		r.Verdict = "PASS: " + gate
	} else {
		r.Verdict = "FAIL: " + gate
	}
	r.Verdict += fmt.Sprintf("; v3 gate %.1fx unmasked, md5() alone %.1fx", r.Ratio, ratio(floor, base))
	return r
}

// benchFindByToken looks up one user by email token, the query an agent uses
// to find a customer. Tokens have no index, so the masked side scans and
// hashes every row; the unmasked side uses an index on the raw email.
func benchFindByToken(ctx context.Context, db *sql.DB, key []byte) result {
	id := min(12345, *rows)
	var raw string
	must(db.QueryRowContext(ctx, fmt.Sprintf("SELECT email FROM %s.users WHERE id = %d", benchSchema, id)).Scan(&raw))
	tok := *token.Token(key, "user.contact.email", token.Email, &raw)
	base := timeQuery(ctx, db, "find by email", fmt.Sprintf("SELECT id FROM %s.users WHERE email = '%s'", benchSchema, raw))
	masked := timeQuery(ctx, db, "find by email token", fmt.Sprintf("SELECT id FROM %s.v_users WHERE email = '%s'", benchSchema, tok))
	return result{
		Query:    "Find one user by email (unmasked: indexed raw email; masked: token, no index)",
		Unmasked: base, Masked: masked, Ratio: ratio(masked, base),
		Verdict: "INFO: known cost until token columns are materialized and indexed",
	}
}

func us(d time.Duration) float64 { return float64(d) / float64(time.Microsecond) }

func benchLookup(ctx context.Context, db *sql.DB) result {
	rng := mrand.New(mrand.NewPCG(42, 42))
	ids := make([]string, *lookupN)
	for i := range ids {
		ids[i] = strconv.Itoa(rng.IntN(*rows) + 1)
	}
	in := strings.Join(ids, ",")
	base := timeQuery(ctx, db, "lookup, unmasked", fmt.Sprintf("SELECT id, email, phone FROM %s.users WHERE id IN (%s)", benchSchema, in))
	masked := timeQuery(ctx, db, "lookup, masked", fmt.Sprintf("SELECT id, email, phone FROM %s.v_users WHERE id IN (%s)", benchSchema, in))
	r := result{Query: fmt.Sprintf("Lookup of %d rows by primary key", *lookupN), Unmasked: base, Masked: masked, Ratio: ratio(masked, base)}
	if masked < lookupBudget {
		r.Verdict = fmt.Sprintf("PASS (< %s)", lookupBudget)
	} else {
		r.Verdict = fmt.Sprintf("FAIL (>= %s)", lookupBudget)
	}
	return r
}

func benchJoin(ctx context.Context, db *sql.DB, e sqlexpr.Engine) result {
	// The unmasked join compares normalized emails, so the ratio isolates
	// the cost of hashing rather than the cost of normalization.
	baseQ := fmt.Sprintf("SELECT count(*) FROM %[1]s.users u JOIN %[1]s.orders o ON %[2]s = %[3]s",
		benchSchema, normExpr(e, emailCol("u.email")), normExpr(e, emailCol("o.customer_email")))
	maskedQ := fmt.Sprintf("SELECT count(*) FROM %[1]s.v_users u JOIN %[1]s.v_orders o ON u.email = o.customer_email", benchSchema)
	for _, q := range []string{baseQ, maskedQ} {
		var n int
		must(db.QueryRowContext(ctx, q).Scan(&n))
		if n != *orders {
			log.Fatalf("join returned %d rows, want %d: %s", n, *orders, q)
		}
	}
	log.Printf("joins return %d rows on both sides", *orders)
	base := timeQuery(ctx, db, "join, unmasked", baseQ)
	masked := timeQuery(ctx, db, "join, masked", maskedQ)
	return result{
		Query:    fmt.Sprintf("Join %d users to %d orders on email token", *rows, *orders),
		Unmasked: base, Masked: masked, Ratio: ratio(masked, base), Verdict: "INFO (no threshold set)",
	}
}

// timeQuery runs q -runs times, reading every row, and returns the median.
func timeQuery(ctx context.Context, db *sql.DB, name, q string) time.Duration {
	var ds []time.Duration
	for i := 0; i < *runs; i++ {
		start := time.Now()
		rs, err := db.QueryContext(ctx, q)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		cols, _ := rs.Columns()
		vals := make([]any, len(cols))
		for j := range vals {
			vals[j] = new(sql.RawBytes)
		}
		for rs.Next() {
			must(rs.Scan(vals...))
		}
		must(rs.Err())
		rs.Close()
		ds = append(ds, time.Since(start))
	}
	slices.Sort(ds)
	med := ds[len(ds)/2]
	log.Printf("%-20s median %s of %d runs", name, med.Round(time.Millisecond), *runs)
	return med
}

func ratio(masked, base time.Duration) float64 {
	if base <= 0 {
		return math.Inf(1)
	}
	return float64(masked) / float64(base)
}

func printReport(r report) {
	fmt.Printf("\n### %s, %d users, %d orders\n\n", r.Engine, r.Rows, r.Orders)
	fmt.Printf("Version: %s. Median of %d runs. %s.\n\n", r.Version, r.Runs, r.When.Format("2006-01-02"))
	fmt.Println("| Query | Unmasked | md5() floor | Masked | Masked / unmasked | Masked / md5 floor | Added per row per column (wall) | CPU per row per column | Verdict |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, x := range r.Results {
		floor, floorRatio, perRow, cpu := "n/a", "n/a", "n/a", "n/a"
		if x.Floor > 0 {
			floor = fmtDur(x.Floor)
			floorRatio = fmt.Sprintf("%.2fx", x.FloorRatio)
			perRow = fmt.Sprintf("%.2f µs", us(x.PerRowCol))
			cpu = fmt.Sprintf("%.2f µs", us(x.CPUPerRowCol))
		}
		fmt.Printf("| %s | %s | %s | %s | %.2fx | %s | %s | %s | %s |\n",
			x.Query, fmtDur(x.Unmasked), floor, fmtDur(x.Masked), x.Ratio, floorRatio, perRow, cpu, x.Verdict)
	}
}

func fmtDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

func mustExec(ctx context.Context, db *sql.DB, q string, args ...any) {
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		log.Fatalf("%v\n%s", err, q)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
