package report

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// MySQL builds the report for one account ("user@host", or "user" when
// only one account has that name) on MySQL 8. db should belong to an
// inspecting account that can read the mysql schema and EXPLAIN the views
// in scope. MySQL has no function that answers "can this account read this
// column", so the report evaluates the grant tables itself. Where it does
// not model something (partial revokes, host matching at login), it
// over-reports: grants are taken to apply everywhere they could.
func MySQL(ctx context.Context, db *sql.DB, account string, cls *classification.File, opts Options) (*Report, error) {
	if opts.Policy != nil {
		var err error
		if opts.Source, err = PolicySource(opts.Policy, "mysql", opts.Source); err != nil {
			return nil, err
		}
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SET SESSION MAX_EXECUTION_TIME = 120000"); err != nil {
		return nil, err
	}
	defer conn.ExecContext(context.Background(), "SET SESSION MAX_EXECUTION_TIME = DEFAULT")
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	s := &myState{ctx: ctx, tx: tx, opts: opts, internal: opts.internal(), report: &Report{Engine: "mysql"}, recognized: map[string]*myRecognized{}, read: map[string]bool{}, matched: map[string]bool{}}
	if cls != nil {
		s.cls = cls.Index()
	}
	var dbname sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT VERSION(), DATABASE()").Scan(&s.report.Version, &dbname); err != nil {
		return nil, err
	}
	s.report.Database = dbname.String
	if !strings.HasPrefix(s.report.Version, "8.") && !strings.HasPrefix(s.report.Version, "9.") {
		return nil, fmt.Errorf("MySQL %s is not supported; need 8.0 or later", s.report.Version)
	}
	steps := []func() error{
		func() error { return s.loadAccount(account) },
		s.loadGrants,
		s.roleFindings,
		s.columnFindings,
		s.viewFindings,
		s.policyFindings,
		s.conditionFindings,
		s.routineFindings,
		s.keyFindings,
		s.settings,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	s.report.sort()
	return s.report, nil
}

// myAccount is the target account or a role it can use.
type myAccount struct {
	user, host string
	chain      string // target > ... > this role
	how        string // "" for the target; how the role is used otherwise
}

func (a myAccount) key() [2]string { return [2]string{a.user, a.host} }
func (a myAccount) String() string { return quoteAccount(a.user, a.host) }

func quoteAccount(user, host string) string {
	return "'" + strings.ReplaceAll(user, "'", "''") + "'@'" + strings.ReplaceAll(host, "'", "''") + "'"
}

type myState struct {
	ctx      context.Context
	tx       *sql.Tx
	opts     Options
	internal string
	cls      map[classification.Key]classification.Column
	report   *Report

	self     myAccount
	accounts []myAccount // self first
	inScope  map[[2]string]bool

	userRows map[[2]string]map[string]string // account -> mysql.user privilege columns
	dynamic  map[[2]string][]string          // account -> dynamic privileges
	dbRows   []myDBGrant
	tblRows  []myTableGrant
	colRows  []myTableGrant
	procRows []myTableGrant
	proxies  [][4]string
	views    map[[2]string]bool // every view on the server
	// recognized holds the view columns that are maskplan transforms.
	recognized map[string]*myRecognized
	read       map[string]bool // views the account can read
	matched    map[string]bool // views that are the policy's
}

type myDBGrant struct {
	account [2]string
	pattern string
	sel     bool
	exec    bool
}

// myTableGrant is a row of tables_priv, columns_priv or procs_priv.
type myTableGrant struct {
	account    [2]string
	db, name   string
	column     string
	privileges string
}

func (s *myState) add(f Finding) { s.report.Findings = append(s.report.Findings, f) }

// via describes how the target uses a.
func (s *myState) via(a myAccount) string {
	if a.how == "" {
		return ""
	}
	return " (" + a.how + ": " + a.chain + ")"
}

var accountRe = regexp.MustCompile(`^'?([^'@]*)'?(?:@'?([^']*)'?)?$`)

func (s *myState) loadAccount(spec string) error {
	m := accountRe.FindStringSubmatch(strings.TrimSpace(spec))
	if m == nil {
		return fmt.Errorf("cannot parse account %q: want user@host", spec)
	}
	user, host := m[1], m[2]
	if !strings.Contains(spec, "@") {
		rows, err := s.tx.QueryContext(s.ctx, "SELECT Host FROM mysql.user WHERE User = ? ORDER BY Host", user)
		if err != nil {
			return err
		}
		var hosts []string
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				rows.Close()
				return err
			}
			hosts = append(hosts, h)
		}
		rows.Close()
		switch len(hosts) {
		case 0:
			return fmt.Errorf("account %q does not exist", user)
		case 1:
			host = hosts[0]
		default:
			return fmt.Errorf("user %q has %d accounts (hosts %s): name one as user@host", user, len(hosts), strings.Join(hosts, ", "))
		}
	} else {
		var n int
		if err := s.tx.QueryRowContext(s.ctx, "SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = ?", user, host).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("account %s does not exist", quoteAccount(user, host))
		}
	}
	s.self = myAccount{user: user, host: host, chain: quoteAccount(user, host)}
	s.report.Role = s.self.String()

	// Every role granted, directly or through roles, can be activated with
	// SET ROLE; default roles are active at login, and with
	// activate_all_roles_on_login all are. Mandatory roles apply to all.
	edges := map[[2]string][][2]string{}
	rows, err := s.tx.QueryContext(s.ctx, "SELECT TO_USER, TO_HOST, FROM_USER, FROM_HOST FROM mysql.role_edges")
	if err != nil {
		return err
	}
	for rows.Next() {
		var tu, th, fu, fh string
		if err := rows.Scan(&tu, &th, &fu, &fh); err != nil {
			rows.Close()
			return err
		}
		edges[[2]string{tu, th}] = append(edges[[2]string{tu, th}], [2]string{fu, fh})
	}
	rows.Close()
	defaults := map[[2]string]bool{}
	rows, err = s.tx.QueryContext(s.ctx, "SELECT DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST FROM mysql.default_roles WHERE USER = ? AND HOST = ?", user, host)
	if err != nil {
		return err
	}
	for rows.Next() {
		var u, h string
		if err := rows.Scan(&u, &h); err != nil {
			rows.Close()
			return err
		}
		defaults[[2]string{u, h}] = true
	}
	rows.Close()
	var mandatory string
	var activateAll bool
	if err := s.tx.QueryRowContext(s.ctx, "SELECT @@GLOBAL.mandatory_roles, @@GLOBAL.activate_all_roles_on_login").Scan(&mandatory, &activateAll); err != nil {
		return err
	}
	seen := map[[2]string]bool{s.self.key(): true}
	s.accounts = []myAccount{s.self}
	queue := []myAccount{s.self}
	for _, r := range parseRoleList(mandatory) {
		if !seen[r] {
			seen[r] = true
			a := myAccount{user: r[0], host: r[1], chain: quoteAccount(r[0], r[1]), how: "mandatory role"}
			s.accounts = append(s.accounts, a)
			queue = append(queue, a)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, r := range edges[cur.key()] {
			if seen[r] {
				continue
			}
			seen[r] = true
			how := "granted role, usable with SET ROLE"
			switch {
			case cur.how == "mandatory role":
				how = "mandatory role"
			case cur.how == "" && (activateAll || defaults[r]):
				how = "granted role, active at login"
			}
			a := myAccount{user: r[0], host: r[1], chain: cur.chain + " > " + quoteAccount(r[0], r[1]), how: how}
			s.accounts = append(s.accounts, a)
			queue = append(queue, a)
		}
	}
	s.inScope = seen
	return nil
}

var roleListRe = regexp.MustCompile("`?([^`@,]+)`?(?:@`?([^`,]+)`?)?")

// parseRoleList parses mandatory_roles: "`r1`@`%`,r2".
func parseRoleList(v string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(v, ",") {
		m := roleListRe.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil || m[1] == "" {
			continue
		}
		host := m[2]
		if host == "" {
			host = "%"
		}
		out = append(out, [2]string{strings.Trim(m[1], "'"), strings.Trim(host, "'")})
	}
	return out
}

var userPrivColumns = []string{"Select_priv", "File_priv", "Super_priv", "Create_user_priv", "Grant_priv", "Repl_slave_priv",
	"Process_priv", "Execute_priv", "Show_view_priv"}

func (s *myState) loadGrants() error {
	s.userRows = map[[2]string]map[string]string{}
	q := "SELECT User, Host, " + strings.Join(userPrivColumns, ", ") + ", COALESCE(JSON_EXTRACT(User_attributes, '$.Restrictions') IS NOT NULL, 0) FROM mysql.user"
	rows, err := s.tx.QueryContext(s.ctx, q)
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]string, len(userPrivColumns)+3)
		dest := make([]any, len(vals))
		for i := range vals {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return err
		}
		k := [2]string{vals[0], vals[1]}
		if !s.inScope[k] {
			continue
		}
		m := map[string]string{"restrictions": vals[len(vals)-1]}
		for i, c := range userPrivColumns {
			m[c] = vals[2+i]
		}
		s.userRows[k] = m
	}
	rows.Close()

	s.dynamic = map[[2]string][]string{}
	rows, err = s.tx.QueryContext(s.ctx, "SELECT USER, HOST, PRIV FROM mysql.global_grants")
	if err != nil {
		return err
	}
	for rows.Next() {
		var u, h, p string
		if err := rows.Scan(&u, &h, &p); err != nil {
			rows.Close()
			return err
		}
		if k := [2]string{u, h}; s.inScope[k] {
			s.dynamic[k] = append(s.dynamic[k], strings.ToUpper(p))
		}
	}
	rows.Close()

	rows, err = s.tx.QueryContext(s.ctx, "SELECT User, Host, Db, Select_priv = 'Y', Execute_priv = 'Y' FROM mysql.db")
	if err != nil {
		return err
	}
	for rows.Next() {
		var g myDBGrant
		if err := rows.Scan(&g.account[0], &g.account[1], &g.pattern, &g.sel, &g.exec); err != nil {
			rows.Close()
			return err
		}
		if s.inScope[g.account] {
			s.dbRows = append(s.dbRows, g)
		}
	}
	rows.Close()

	load := func(q string, withColumn bool, dst *[]myTableGrant) error {
		rows, err := s.tx.QueryContext(s.ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g myTableGrant
			dest := []any{&g.account[0], &g.account[1], &g.db, &g.name}
			if withColumn {
				dest = append(dest, &g.column)
			}
			dest = append(dest, &g.privileges)
			if err := rows.Scan(dest...); err != nil {
				return err
			}
			if s.inScope[g.account] {
				*dst = append(*dst, g)
			}
		}
		return rows.Err()
	}
	if err := load("SELECT User, Host, Db, Table_name, Table_priv FROM mysql.tables_priv", false, &s.tblRows); err != nil {
		return err
	}
	if err := load("SELECT User, Host, Db, Table_name, Column_name, Column_priv FROM mysql.columns_priv", true, &s.colRows); err != nil {
		return err
	}
	if err := load("SELECT User, Host, Db, Routine_name, Proc_priv FROM mysql.procs_priv", false, &s.procRows); err != nil {
		return err
	}
	rows, err = s.tx.QueryContext(s.ctx, "SELECT User, Host, Proxied_user, Proxied_host FROM mysql.proxies_priv")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p [4]string
		if err := rows.Scan(&p[0], &p[1], &p[2], &p[3]); err != nil {
			return err
		}
		if s.inScope[[2]string{p[0], p[1]}] {
			s.proxies = append(s.proxies, p)
		}
	}
	return rows.Err()
}

// dbPatternMatch reports whether a mysql.db Db value matches db. Db may
// hold LIKE wildcards (_ and %), escaped with a backslash to be literal.
func dbPatternMatch(pattern, db string) bool {
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '\\' && i+1 < len(pattern):
			i++
			re.WriteString(regexp.QuoteMeta(string(pattern[i])))
		case c == '%':
			re.WriteString(".*")
		case c == '_':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	ok, _ := regexp.MatchString(re.String(), db)
	return ok
}

func hasPriv(set, priv string) bool {
	for _, p := range strings.Split(set, ",") {
		if strings.EqualFold(strings.TrimSpace(p), priv) {
			return true
		}
	}
	return false
}

// selectPaths lists the grants by which the target can SELECT the column
// (or, with column "", every column of the table).
func (s *myState) selectPaths(db, table, column string) []string {
	var out []string
	for _, a := range s.accounts {
		k := a.key()
		v := s.via(a)
		if s.userRows[k]["Select_priv"] == "Y" {
			out = append(out, "global SELECT granted to "+a.String()+v)
			continue
		}
		for _, g := range s.dbRows {
			if g.account == k && g.sel && dbPatternMatch(g.pattern, db) {
				out = append(out, fmt.Sprintf("SELECT on `%s`.* granted to %s%s", g.pattern, a, v))
			}
		}
		for _, g := range s.tblRows {
			if g.account == k && g.db == db && g.name == table && hasPriv(g.privileges, "Select") {
				out = append(out, "SELECT on the table granted to "+a.String()+v)
			}
		}
		if column == "" {
			continue
		}
		for _, g := range s.colRows {
			if g.account == k && g.db == db && g.name == table && g.column == column && hasPriv(g.privileges, "Select") {
				out = append(out, "SELECT on the column granted to "+a.String()+v)
			}
		}
	}
	return out
}

func (s *myState) userPriv(a myAccount, col string) bool { return s.userRows[a.key()][col] == "Y" }

func (s *myState) hasDynamic(a myAccount, priv string) bool {
	for _, p := range s.dynamic[a.key()] {
		if p == priv {
			return true
		}
	}
	return false
}

func (s *myState) roleFindings() error {
	unknown := map[string]string{
		"File_priv":        "FILE: can read any file the server can (LOAD_FILE, LOAD DATA), bypassing table privileges",
		"Super_priv":       "SUPER: can change server settings and act beyond table privileges",
		"Create_user_priv": "CREATE USER: can create accounts and grant them privileges it holds",
		"Grant_priv":       "global GRANT OPTION: can pass on any privilege it holds",
		"Repl_slave_priv":  "REPLICATION SLAVE: can stream the binary log, every change to every table",
	}
	dynUnknown := map[string]string{
		"SET_USER_ID":     "SET_USER_ID: can create views and routines that run as any account",
		"SET_ANY_DEFINER": "SET_ANY_DEFINER: can create views and routines that run as any account",
		"ROLE_ADMIN":      "ROLE_ADMIN: can grant itself any role",
		"BACKUP_ADMIN":    "BACKUP_ADMIN: can take a backup of the whole server",
		"CLONE_ADMIN":     "CLONE_ADMIN: can clone the whole server",
	}
	for _, a := range s.accounts {
		for _, col := range userPrivColumns {
			if why, ok := unknown[col]; ok && s.userPriv(a, col) {
				s.add(Finding{Status: Unknown, Object: "account", Path: why + "; held by " + a.String() + s.via(a)})
			}
		}
		for p, why := range dynUnknown {
			if s.hasDynamic(a, p) {
				s.add(Finding{Status: Unknown, Object: "account", Path: why + "; held by " + a.String() + s.via(a)})
			}
		}
		if s.userPriv(a, "Process_priv") {
			s.add(Finding{Status: Warn, Object: "account", Path: "PROCESS: sees the statements of every session, including literal values in them; held by " + a.String() + s.via(a)})
		}
		if s.hasDynamic(a, "AUDIT_ADMIN") {
			s.add(Finding{Status: Warn, Object: "account", Path: "AUDIT_ADMIN: can change what the audit log records; held by " + a.String() + s.via(a)})
		}
		if s.userRows[a.key()]["restrictions"] == "1" {
			s.add(Finding{Status: Warn, Object: "account", Path: "partial revokes on " + a.String() + " are not evaluated: its global grants are taken to apply everywhere"})
		}
	}
	for _, p := range s.proxies {
		s.add(Finding{Status: Unknown, Object: "account", Path: fmt.Sprintf("PROXY: %s can act as %s, with that account's privileges", quoteAccount(p[0], p[1]), quoteAccount(p[2], p[3]))})
	}
	// Account password hashes.
	if paths := s.selectPaths("mysql", "user", "authentication_string"); len(paths) > 0 {
		s.add(Finding{Status: Unknown, Object: "mysql.user", Path: "can read account password hashes: " + strings.Join(paths, "; ")})
	}
	var anonymous int
	if err := s.tx.QueryRowContext(s.ctx, "SELECT COUNT(*) FROM mysql.user WHERE User = ''").Scan(&anonymous); err != nil {
		return err
	}
	if anonymous > 0 {
		s.add(Finding{Status: Warn, Object: "server", Path: fmt.Sprintf("%d anonymous accounts exist: a connection may match one instead of the intended account", anonymous)})
	}
	return nil
}

// relationColumns lists the columns of base tables or views in scope.
func (s *myState) relationColumns(tableType string) ([][3]string, error) {
	q := `SELECT c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME FROM information_schema.COLUMNS c
		JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
		WHERE t.TABLE_TYPE = ? AND c.TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') AND c.TABLE_SCHEMA <> ?`
	args := []any{tableType, s.internal}
	if len(s.opts.Schemas) > 0 {
		q += " AND c.TABLE_SCHEMA IN (?" + strings.Repeat(", ?", len(s.opts.Schemas)-1) + ")"
		for _, x := range s.opts.Schemas {
			args = append(args, x)
		}
	}
	q += " ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION"
	rows, err := s.tx.QueryContext(s.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var r [3]string
		if err := rows.Scan(&r[0], &r[1], &r[2]); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *myState) columnFindings() error {
	cols, err := s.relationColumns("BASE TABLE")
	if err != nil {
		return err
	}
	for _, c := range cols {
		paths := s.selectPaths(c[0], c[1], c[2])
		if len(paths) == 0 {
			continue
		}
		obj := c[0] + "." + c[1] + "." + c[2]
		path := strings.Join(paths, "; ")
		l, ok := s.cls[classification.Key{Schema: c[0], Table: c[1], Column: c[2]}]
		switch {
		case !ok:
			s.add(Finding{Status: Unlabeled, Object: obj, Path: "readable raw; not in the classification, scan again: " + path})
		case l.IsPII() && l.DerivedFrom != "":
			s.add(Finding{Status: Unknown, Object: obj, Label: l.Label, Path: derivedPath(c[0], c[1], l) + ": " + path})
		case l.IsPII():
			s.add(Finding{Status: Raw, Object: obj, Label: l.Label, Path: path})
		}
	}
	return nil
}

// myLineage is what the optimizer says one view column is.
type myLineage struct {
	expr        string // select expression, as rewritten by the optimizer
	from        map[string][2]string
	refs        [][3]string // alias, column, raw text
	untraceable string
}

var (
	myRefRe     = regexp.MustCompile("`((?:[^`]|``)+)`\\.`((?:[^`]|``)+)`\\.`((?:[^`]|``)+)`")
	myLiteralRe = regexp.MustCompile(`'(?:[^'\\]|\\.|'')*'`)
	myFromRe    = regexp.MustCompile("`((?:[^`]|``)+)`\\.`((?:[^`]|``)+)` `((?:[^`]|``)+)`")
)

// explainMySQL runs EXPLAIN FORMAT=JSON on query and returns the plan and
// the optimizer's rewritten statement (SHOW WARNINGS, note 1003).
func (s *myState) explainMySQL(query string) (map[string]any, string, error) {
	var plan string
	if err := s.tx.QueryRowContext(s.ctx, "EXPLAIN FORMAT=JSON "+query).Scan(&plan); err != nil {
		return nil, "", err
	}
	rows, err := s.tx.QueryContext(s.ctx, "SHOW WARNINGS")
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var rewritten string
	for rows.Next() {
		var level, msg string
		var code int
		if err := rows.Scan(&level, &code, &msg); err != nil {
			return nil, "", err
		}
		if code == 1003 {
			rewritten = msg
		}
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(plan), &p); err != nil {
		return nil, "", err
	}
	return p, rewritten, rows.Err()
}

// planTables collects the access type of every table in a plan, and any
// message (No tables used, Impossible WHERE).
func planTables(v any, f func(name, access, message string)) {
	switch x := v.(type) {
	case map[string]any:
		if t, ok := x["table"].(map[string]any); ok {
			name, _ := t["table_name"].(string)
			access, _ := t["access_type"].(string)
			f(name, access, "")
		}
		if m, ok := x["message"].(string); ok {
			f("", "", m)
		}
		for _, e := range x {
			planTables(e, f)
		}
	case []any:
		for _, e := range x {
			planTables(e, f)
		}
	}
}

// selectExpr splits "/* select#1 */ select EXPR AS `alias` from REST" for a
// one-column query, honoring quotes and parentheses.
func selectExpr(rewritten, alias string) (expr, from string, ok bool) {
	const prefix = "/* select#1 */ select "
	if !strings.HasPrefix(rewritten, prefix) {
		return "", "", false
	}
	body := rewritten[len(prefix):]
	marker := " AS `" + strings.ReplaceAll(alias, "`", "``") + "`"
	depth, quote := 0, byte(0)
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '\'' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '`' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && strings.HasPrefix(body[i:], marker):
			rest := strings.TrimPrefix(body[i+len(marker):], " ")
			return body[:i], rest, true
		}
	}
	return "", "", false
}

func unquoteMy(id string) string { return strings.ReplaceAll(id, "``", "`") }

// lineage traces one view column. It refuses (untraceable) whenever the
// optimizer read a data table as a constant: then values from the data
// appear in the rewritten statement in place of column references, and a
// raw column could look like a literal.
func (s *myState) lineage(db, view, col string) (*myLineage, error) {
	q := fmt.Sprintf("SELECT %s FROM %s.%s", quoteMy(col), quoteMy(db), quoteMy(view))
	plan, rewritten, err := s.explainMySQL(q)
	if err != nil {
		return nil, err
	}
	l := &myLineage{from: map[string][2]string{}}
	expr, from, ok := selectExpr(rewritten, col)
	if !ok {
		l.untraceable = "cannot parse the optimizer's rewritten statement"
		return l, nil
	}
	l.expr = expr
	for _, m := range myFromRe.FindAllStringSubmatch(from, -1) {
		l.from[unquoteMy(m[3])] = [2]string{unquoteMy(m[1]), unquoteMy(m[2])}
	}
	// Tables written without an alias appear as `db`.`table`.
	for _, m := range regexp.MustCompile("`((?:[^`]|``)+)`\\.`((?:[^`]|``)+)`").FindAllStringSubmatch(from, -1) {
		if _, ok := l.from[unquoteMy(m[2])]; !ok {
			l.from[unquoteMy(m[2])] = [2]string{unquoteMy(m[1]), unquoteMy(m[2])}
		}
	}
	planTables(plan, func(name, access, message string) {
		if message != "" && l.untraceable == "" {
			l.untraceable = "the optimizer reports: " + message
		}
		if (access == "const" || access == "system") && l.untraceable == "" {
			if base, ok := l.from[name]; !ok || !(base[0] == s.internal && base[1] == "key_material") {
				l.untraceable = "the optimizer read " + name + " as a constant, so its values replace column references; trace it on more rows"
			}
		}
	})
	stripped := myLiteralRe.ReplaceAllString(expr, "''")
	if strings.Contains(stripped, "select#") {
		l.untraceable = "value computed by a subquery"
	}
	for _, m := range myRefRe.FindAllStringSubmatch(stripped, -1) {
		l.refs = append(l.refs, [3]string{unquoteMy(m[2]), unquoteMy(m[3]), m[0]})
	}
	if len(l.refs) == 0 && l.untraceable == "" && strings.Contains(from, "dual") {
		l.untraceable = "the optimizer folded the column to a constant"
	}
	return l, nil
}

func quoteMy(id string) string { return "`" + strings.ReplaceAll(id, "`", "``") + "`" }

var (
	myTokenLabelRe = regexp.MustCompile(`'([a-z0-9_.]+):'`)
	myTokenLenRe   = regexp.MustCompile(`,(\d+)\)\)$`)
	my2PartRe      = regexp.MustCompile("`((?:[^`]|``)+)`\\.`((?:[^`]|``)+)`")
	// A column reference qualified with its database, as the optimizer
	// prints it: `db`.`alias`.`column`.
	my3PartRe = regexp.MustCompile("`(?:[^`]|``)+`\\.(`(?:[^`]|``)+`\\.`(?:[^`]|``)+`)")
)

// splitTopLevel splits s at sep outside quotes and parentheses.
func splitTopLevel(s string, sep string) []string {
	var out []string
	depth, quote, start := 0, byte(0), 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '\'' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '`' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], sep):
			out = append(out, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(out, s[start:])
}

// viewDefinition parses a view's stored definition (information_schema
// .VIEWS): the expression of each output column, and the relations of its
// FROM clause by alias. Unlike the optimizer's rewrite, it never contains
// values from the data or the key.
func (s *myState) viewDefinition(db, view string) (map[string]string, map[string][2]string, error) {
	var def string
	err := s.tx.QueryRowContext(s.ctx, "SELECT VIEW_DEFINITION FROM information_schema.VIEWS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?", db, view).Scan(&def)
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(def, "select ") {
		return nil, nil, nil
	}
	parts := splitTopLevel(def[len("select "):], " from ")
	if len(parts) != 2 {
		return nil, nil, nil
	}
	exprs := map[string]string{}
	for _, item := range splitTopLevel(parts[0], ",") {
		k := strings.LastIndex(item, " AS `")
		if k < 0 || !strings.HasSuffix(item, "`") {
			return nil, nil, nil
		}
		exprs[unquoteMy(item[k+len(" AS `"):len(item)-1])] = item[:k]
	}
	from := map[string][2]string{}
	for _, m := range myFromRe.FindAllStringSubmatch(parts[1], -1) {
		from[unquoteMy(m[3])] = [2]string{unquoteMy(m[1]), unquoteMy(m[2])}
	}
	return exprs, from, nil
}

// myRecognized is a view column that is exactly a maskplan transform of
// one base column.
type myRecognized struct {
	transform string
	params    map[string]any
	base      [2]string
	col       string
}

var myPrefixLenRe = regexp.MustCompile(`^left\(.*,(\d+)\)$`)

// recognize reports whether a view column is exactly a maskplan transform
// of one base column, with the key read from the key table. It compares the
// view's stored definition of the column with the optimizer's printing of a
// reference query built by the compiler on the same aliases. The reference
// joins the key table on a condition that is not constant, so the pads print
// as column references, as in the definition, and not as values. Fake values
// also need their dictionary join: its index expression is compared the
// same way.
func (s *myState) recognize(db, view, col string) (*myRecognized, error) {
	exprs, from, err := s.viewDefinition(db, view)
	if err != nil || exprs == nil {
		return nil, err
	}
	expr, ok := exprs[col]
	if !ok {
		return nil, nil
	}
	keyAlias := ""
	for alias, rel := range from {
		if rel == [2]string{s.internal, "key_material"} {
			keyAlias = alias
		}
	}
	// The base column: every reference that is not to maskplan's tables.
	var alias, column string
	for _, m := range my2PartRe.FindAllStringSubmatch(myLiteralRe.ReplaceAllString(expr, "''"), -1) {
		a, c := unquoteMy(m[1]), unquoteMy(m[2])
		if a == keyAlias {
			continue
		}
		if alias != "" && (a != alias || c != column) {
			return nil, nil
		}
		alias, column = a, c
	}
	type candidate struct {
		transform, expr, join string
		params                map[string]any
	}
	var cands []candidate
	pads := sqlexpr.Pads{IPad: quoteMy(keyAlias) + ".`ipad`", OPad: quoteMy(keyAlias) + ".`opad`"}
	if rel, ok := from[alias]; ok && rel == [2]string{s.internal, "names"} && column == "name" {
		// fake_name, fake_email: the base column is in the dictionary
		// join, named by its alias.
		fakeAlias := alias
		var label string
		if alias, column, label, ok = s.fakeJoin(db, view, from, keyAlias, fakeAlias); !ok {
			return nil, nil
		}
		for _, t := range []string{policy.FakeName, policy.FakeEmail} {
			e, j, err := compile.ColumnSQL(sqlexpr.MySQL, policy.Decision{Transform: t, Label: label}, compile.Column{Name: column}, alias, pads, s.internal)
			if err != nil || !strings.Contains(j, quoteMy(fakeAlias)) {
				return nil, nil
			}
			cands = append(cands, candidate{t, e, j, nil})
		}
	} else if lm, nm := myTokenLabelRe.FindStringSubmatch(expr), myTokenLenRe.FindStringSubmatch(expr); keyAlias != "" && lm != nil && nm != nil {
		var n int
		fmt.Sscanf(nm[1], "%d", &n)
		ref := quoteMy(alias) + "." + quoteMy(column)
		for _, norm := range []token.Normalizer{token.Email, token.Phone, token.Trim} {
			t, err := sqlexpr.Token(sqlexpr.MySQL, sqlexpr.Column{Expr: ref, Label: lm[1], Normalizer: norm, TokenHexLen: n}, pads)
			if err != nil {
				return nil, nil
			}
			cands = append(cands, candidate{policy.Token, t, "", nil})
		}
	} else {
		c := compile.Column{Name: column, Category: "D"}
		ds := []policy.Decision{{Transform: policy.GeneralizeYear}, {Transform: policy.GeneralizeMonth}}
		if m := myPrefixLenRe.FindStringSubmatch(expr); m != nil {
			var n int
			if _, err := fmt.Sscanf(m[1], "%d", &n); err == nil {
				ds = append(ds, policy.Decision{Transform: policy.Prefix, Params: map[string]any{"keep": n}})
			}
		}
		for _, d := range ds {
			if e, j, err := compile.ColumnSQL(sqlexpr.MySQL, d, c, alias, pads, s.internal); err == nil {
				cands = append(cands, candidate{d.Transform, e, j, d.Params})
			}
		}
	}
	base, ok := from[alias]
	if alias == "" || !ok || s.views[base] || base[0] == s.internal {
		return nil, nil
	}
	for _, c := range cands {
		if want, ok := s.printed(c.expr, base, alias, column, keyAlias, c.join); ok && want == expr {
			return &myRecognized{transform: c.transform, params: c.params, base: base, col: column}, nil
		}
	}
	return nil, nil
}

// fakeJoin checks that the dictionary join aliased fakeAlias is the one
// maskplan generates: its index expression equals the printing of the
// generated one for column fake_<column> of the view's one base table. It
// returns that table's alias, the column and its label.
func (s *myState) fakeJoin(db, view string, from map[string][2]string, keyAlias, fakeAlias string) (alias, column, label string, ok bool) {
	column, ok = strings.CutPrefix(fakeAlias, "fake_")
	if !ok || keyAlias == "" || from[fakeAlias] != [2]string{s.internal, "names"} {
		return "", "", "", false
	}
	for a, rel := range from {
		if rel[0] != s.internal {
			if alias != "" {
				return "", "", "", false
			}
			alias = a
		}
	}
	if alias == "" {
		return "", "", "", false
	}
	label = s.cls[classification.Key{Schema: from[alias][0], Table: from[alias][1], Column: column}].Label
	idx, ok := fakeIndexExpr(s.viewFrom(db, view), s.internal, fakeAlias)
	if !ok {
		return "", "", "", false
	}
	pads := sqlexpr.Pads{IPad: quoteMy(keyAlias) + ".`ipad`", OPad: quoteMy(keyAlias) + ".`opad`"}
	x, err := sqlexpr.FakeIndex(sqlexpr.MySQL, sqlexpr.Column{Expr: quoteMy(alias) + "." + quoteMy(column), Label: unlabeledOr(label), Normalizer: compile.NormalizerFor(label)}, pads, compile.DictionarySize)
	if err != nil {
		return "", "", "", false
	}
	if want, ok := s.printed(x, from[alias], alias, column, keyAlias, ""); !ok || want != idx {
		return "", "", "", false
	}
	return alias, column, label, true
}

func unlabeledOr(label string) string {
	if label == "" || label == classification.None {
		return "maskplan.unlabeled"
	}
	return label
}

// printed returns how the optimizer prints expr as a select expression of
// a reference query over base (aliased alias), with the key table joined
// on a condition that is not constant and the extra join, with database
// qualifiers removed as in a stored view definition.
func (s *myState) printed(expr string, base [2]string, alias, column, keyAlias, join string) (string, bool) {
	keyJoin := ""
	if keyAlias != "" {
		// The condition must depend on the row in a way the optimizer
		// cannot fold: on a NOT NULL column it folds "x IS NULL" to false,
		// reads the key table as a constant and prints the pads as values.
		keyJoin = fmt.Sprintf(" JOIN %s.`key_material` %s ON %s.`id` = 1 + 0 * CRC32(%s.%s)",
			quoteMy(s.internal), quoteMy(keyAlias), quoteMy(keyAlias), quoteMy(alias), quoteMy(column))
	}
	q := fmt.Sprintf("SELECT %s AS maskplan_ref FROM %s.%s %s%s%s", expr, quoteMy(base[0]), quoteMy(base[1]), quoteMy(alias), keyJoin, strings.ReplaceAll(join, "\n", " "))
	_, rewritten, err := s.explainMySQL(q)
	if err != nil {
		return "", false
	}
	want, _, ok := selectExpr(rewritten, "maskplan_ref")
	return my3PartRe.ReplaceAllString(want, "$1"), ok
}

// viewFrom returns the FROM clause of a view's stored definition.
func (s *myState) viewFrom(db, view string) string {
	var def string
	if err := s.tx.QueryRowContext(s.ctx, "SELECT VIEW_DEFINITION FROM information_schema.VIEWS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?", db, view).Scan(&def); err != nil {
		return ""
	}
	if !strings.HasPrefix(def, "select ") {
		return ""
	}
	parts := splitTopLevel(def[len("select "):], " from ")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// fakeIndexExpr finds the dictionary join of alias in a stored FROM clause,
// "left join `internal`.`names` `alias` on((`alias`.`i` = EXPR))", and
// returns EXPR. It must occur exactly once.
func fakeIndexExpr(from, internal, alias string) (string, bool) {
	marker := "left join " + quoteMy(internal) + ".`names` " + quoteMy(alias) + " on((" + quoteMy(alias) + ".`i` = "
	i := strings.Index(from, marker)
	if i < 0 || strings.Count(from, marker) != 1 {
		return "", false
	}
	rest := from[i+len(marker):]
	depth, quote := 0, byte(0)
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		switch {
		case quote != 0:
			if c == '\\' && quote == '\'' {
				j++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '`' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				if strings.HasPrefix(rest[j:], "))") {
					return rest[:j], true
				}
				return "", false
			}
			depth--
		}
	}
	return "", false
}

func (s *myState) viewFindings() error {
	cols, err := s.relationColumns("VIEW")
	if err != nil {
		return err
	}
	s.views = map[[2]string]bool{}
	vrows, err := s.tx.QueryContext(s.ctx, "SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.VIEWS")
	if err != nil {
		return err
	}
	for vrows.Next() {
		var k [2]string
		if err := vrows.Scan(&k[0], &k[1]); err != nil {
			vrows.Close()
			return err
		}
		s.views[k] = true
	}
	vrows.Close()
	for _, c := range cols {
		paths := s.selectPaths(c[0], c[1], c[2])
		if len(paths) == 0 {
			continue
		}
		obj := c[0] + "." + c[1] + "." + c[2]
		s.read[c[0]+"."+c[1]] = true
		access := "view: " + strings.Join(paths, "; ")
		l, err := s.lineage(c[0], c[1], c[2])
		if err != nil {
			s.add(Finding{Status: Unknown, Object: obj, Path: fmt.Sprintf("cannot trace view column (EXPLAIN failed: %v); %s", err, access)})
			continue
		}
		// Print the stored definition, never the optimizer's rewrite: the
		// rewrite holds values from constant tables, data and key alike.
		short := ""
		if exprs, _, err := s.viewDefinition(c[0], c[1]); err == nil && exprs != nil {
			short = printableExpr(exprs[c[2]])
		}
		type ref struct {
			base         [2]string
			alias, col   string
			raw          string
			label        classification.Column
			labeled, pii bool
		}
		var refs []ref
		unresolved := false
		for _, r := range l.refs {
			base, ok := l.from[r[0]]
			if !ok || s.views[base] {
				// A view the optimizer materialized rather than merged.
				unresolved = true
				continue
			}
			lab, labeled := s.cls[classification.Key{Schema: base[0], Table: base[1], Column: r[1]}]
			refs = append(refs, ref{base: base, alias: r[0], col: r[1], raw: r[2], label: lab, labeled: labeled, pii: labeled && lab.IsPII()})
		}
		var pii, unlabeled []ref
		for _, r := range refs {
			if r.pii {
				pii = append(pii, r)
			} else if !r.labeled && !(r.base[0] == s.internal && r.base[1] == "key_material") {
				unlabeled = append(unlabeled, r)
			}
		}
		passthrough := l.untraceable == "" && len(pii) == 1 && len(l.refs) == 1 && strings.TrimSpace(l.expr) == pii[0].raw
		rec, err := s.recognize(c[0], c[1], c[2])
		if err != nil {
			return err
		}
		if rec != nil {
			s.recognized[c[0]+"."+c[1]+"."+c[2]] = rec
		}
		base := func(r ref) string { return r.base[0] + "." + r.base[1] + "." + r.col }
		switch {
		case passthrough && pii[0].label.DerivedFrom != "":
			s.add(Finding{Status: Unknown, Object: obj, Label: pii[0].label.Label, Path: "passes through " + derivedPath(pii[0].base[0], pii[0].base[1], pii[0].label) + "; " + access})
		case passthrough:
			s.add(Finding{Status: Raw, Object: obj, Label: pii[0].label.Label, Path: "passes through " + base(pii[0]) + "; " + access})
		case rec != nil:
			lab := s.cls[classification.Key{Schema: rec.base[0], Table: rec.base[1], Column: rec.col}]
			s.add(Finding{Status: Masked, Object: obj, Label: lab.Label, Path: "maskplan " + rec.transform + " of " + rec.base[0] + "." + rec.base[1] + "." + rec.col})
		case l.untraceable != "":
			s.add(Finding{Status: Unknown, Object: obj, Path: "cannot trace view column to base columns (" + l.untraceable + "): " + short + "; " + access})
		case len(pii) > 0:
			s.add(Finding{Status: Unknown, Object: obj, Label: pii[0].label.Label, Path: "expression over " + base(pii[0]) + " is not a maskplan transform: " + short + "; " + access})
		case unresolved:
			s.add(Finding{Status: Unknown, Object: obj, Path: "cannot trace view column to base columns: " + short + "; " + access})
		case len(unlabeled) > 0:
			s.add(Finding{Status: Unlabeled, Object: obj, Path: "exposes " + base(unlabeled[0]) + ", which is not in the classification; " + access})
		}
	}
	return nil
}

// routineFindings flags SQL SECURITY DEFINER routines the target can run:
// they execute with their definer's privileges, which the report does not
// trace.
func (s *myState) routineFindings() error {
	q := `SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, DEFINER FROM information_schema.ROUTINES
		WHERE SECURITY_TYPE = 'DEFINER' AND ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')`
	args := []any{}
	if len(s.opts.Schemas) > 0 {
		q += " AND ROUTINE_SCHEMA IN (?" + strings.Repeat(", ?", len(s.opts.Schemas)-1) + ")"
		for _, x := range s.opts.Schemas {
			args = append(args, x)
		}
	}
	rows, err := s.tx.QueryContext(s.ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var db, name, kind, definer string
		if err := rows.Scan(&db, &name, &kind, &definer); err != nil {
			return err
		}
		var how []string
		for _, a := range s.accounts {
			k, v := a.key(), s.via(a)
			if s.userPriv(a, "Execute_priv") {
				how = append(how, "global EXECUTE granted to "+a.String()+v)
				continue
			}
			for _, g := range s.dbRows {
				if g.account == k && g.exec && dbPatternMatch(g.pattern, db) {
					how = append(how, fmt.Sprintf("EXECUTE on `%s`.* granted to %s%s", g.pattern, a, v))
				}
			}
			for _, g := range s.procRows {
				if g.account == k && g.db == db && strings.EqualFold(g.name, name) && hasPriv(g.privileges, "Execute") {
					how = append(how, "EXECUTE on the routine granted to "+a.String()+v)
				}
			}
		}
		if len(how) > 0 {
			s.add(Finding{Status: Unknown, Object: strings.ToLower(kind) + " " + db + "." + name,
				Path: "SQL SECURITY DEFINER, runs as " + definer + ", whose privileges are not traced; " + strings.Join(how, "; ")})
		}
	}
	return rows.Err()
}

func (s *myState) keyFindings() error {
	var exists int
	if err := s.tx.QueryRowContext(s.ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'key_material'`, s.internal).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	obj := s.internal + ".key_material"
	var paths []string
	for _, c := range []string{"id", "ipad", "opad"} {
		paths = append(paths, s.selectPaths(s.internal, "key_material", c)...)
	}
	if len(paths) > 0 {
		s.add(Finding{Status: Key, Object: obj, Path: "can read the token key material: " + strings.Join(dedupe(paths), "; ") + "; every token can be reversed by guessing"})
	}
	var ipad, opad []byte
	var n int
	if err := s.tx.QueryRowContext(s.ctx, "SELECT COUNT(*) FROM "+quoteMy(s.internal)+".key_material").Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		s.add(Finding{Status: Warn, Object: obj, Path: fmt.Sprintf("has %d rows, want exactly 1: with none, every token is NULL", n)})
	} else {
		if err := s.tx.QueryRowContext(s.ctx, "SELECT ipad, opad FROM "+quoteMy(s.internal)+".key_material").Scan(&ipad, &opad); err != nil {
			return err
		}
		if err := s.keyLiteralFindings(ipad, opad); err != nil {
			return err
		}
	}
	var logBin int
	if err := s.tx.QueryRowContext(s.ctx, "SELECT @@GLOBAL.log_bin").Scan(&logBin); err != nil {
		return err
	}
	if logBin == 1 {
		s.add(Finding{Status: Warn, Object: obj, Path: "binary logging is on: the statement that stored the key is in the binary log, which REPLICATION SLAVE and anyone with the log files can read; rotate the key after purging old logs"})
	}
	return nil
}

// keyLiteralFindings looks for the pads written into view or routine
// definitions, in hex or as text.
func (s *myState) keyLiteralFindings(ipad, opad []byte) error {
	needles := []string{hex.EncodeToString(ipad), hex.EncodeToString(opad)}
	for _, p := range [][]byte{ipad, opad} {
		if printable(p) {
			needles = append(needles, strings.ToLower(string(p)))
		}
	}
	for _, src := range []struct{ kind, q string }{
		{"view", "SELECT TABLE_SCHEMA, TABLE_NAME, LOWER(VIEW_DEFINITION) FROM information_schema.VIEWS WHERE TABLE_SCHEMA NOT IN ('sys', 'mysql')"},
		{"routine", "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, LOWER(COALESCE(ROUTINE_DEFINITION, '')) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('sys', 'mysql')"},
	} {
		rows, err := s.tx.QueryContext(s.ctx, src.q)
		if err != nil {
			return err
		}
		for rows.Next() {
			var db, name, def string
			if err := rows.Scan(&db, &name, &def); err != nil {
				rows.Close()
				return err
			}
			for _, needle := range needles {
				if needle != "" && strings.Contains(def, needle) {
					s.add(Finding{Status: Key, Object: src.kind + " " + db + "." + name, Path: "its definition contains the token key material"})
					break
				}
			}
		}
		rows.Close()
	}
	return nil
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func (s *myState) settings() error {
	st := &s.report.Settings
	var plugin, locked, expired string
	var maxConn int
	err := s.tx.QueryRowContext(s.ctx, "SELECT plugin, account_locked, password_expired, max_user_connections FROM mysql.user WHERE User = ? AND Host = ?",
		s.self.user, s.self.host).Scan(&plugin, &locked, &expired, &maxConn)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("account %s disappeared", s.self)
	} else if err != nil {
		return err
	}
	switch {
	case locked == "Y":
		st.Login = "account locked: cannot log in; reachable only as a role"
	case plugin == "AWSAuthenticationPlugin":
		st.Login = "IAM token (AWSAuthenticationPlugin)"
	case plugin == "auth_socket":
		st.Login = "Unix socket identity (auth_socket)"
	case plugin == "authentication_ldap_simple" || plugin == "authentication_ldap_sasl" || plugin == "authentication_kerberos":
		st.Login = "directory (" + plugin + ")"
	default:
		st.Login = "password (" + plugin + ")"
	}
	if expired == "Y" {
		st.Login += "; password expired"
	}
	st.ConnectionLimit = "none"
	if maxConn > 0 {
		st.ConnectionLimit = fmt.Sprintf("%d (enforced)", maxConn)
	}
	rows, err := s.tx.QueryContext(s.ctx, `SELECT PLUGIN_NAME FROM information_schema.PLUGINS
		WHERE PLUGIN_STATUS = 'ACTIVE' AND PLUGIN_NAME IN ('audit_log', 'server_audit', 'SERVER_AUDIT', 'audit_log_filter')`)
	if err != nil {
		return err
	}
	var audit []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		audit = append(audit, p)
	}
	rows.Close()
	if len(audit) > 0 {
		st.Audit = "audit plugin " + strings.Join(audit, ", ") + " is active; check that its filter covers this account's reads"
	} else {
		st.Audit = "none: no audit plugin is active, so reads by this account are not logged"
	}
	var timeout int
	if err := s.tx.QueryRowContext(s.ctx, "SELECT @@GLOBAL.max_execution_time").Scan(&timeout); err != nil {
		return err
	}
	st.StatementTimeout = "none"
	if timeout > 0 {
		st.StatementTimeout = fmt.Sprintf("%d ms for SELECT (server default; the session can override it)", timeout)
	}
	return nil
}
