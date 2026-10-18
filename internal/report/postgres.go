package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// Options narrows a report.
type Options struct {
	// Schemas limits the report to these schemas; empty means every
	// non-system schema.
	Schemas []string
	// InternalSchema holds maskplan's key table; default maskplan_internal.
	InternalSchema string
}

func (o Options) internal() string {
	if o.InternalSchema == "" {
		return "maskplan_internal"
	}
	return o.InternalSchema
}

// pgRole is a role the target can act as: itself, or a role reachable
// through membership by inheritance or SET ROLE.
type pgRole struct {
	oid        uint32
	name       string
	inherited  bool   // every membership edge on the path inherits privileges
	chain      string // target > ... > this role
	super      bool
	createrole bool
	bypassrls  bool
	repl       bool
}

type pgState struct {
	ctx      context.Context
	tx       pgx.Tx
	version  int
	self     uint32
	roles    map[uint32]*pgRole
	order    []uint32 // self first
	cls      map[classification.Key]classification.Column
	opts     Options
	report   *Report
	roots    map[[2]string]string // schema, partition -> root table
	internal string
}

// Postgres builds the report for role. conn should belong to an inspecting
// user that can read the catalog and run EXPLAIN on the views in scope, such
// as the database owner or an admin role; the report runs in a read-only
// transaction.
func Postgres(ctx context.Context, conn *pgx.Conn, role string, cls *classification.File, opts Options) (*Report, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// With only pg_catalog on the search path, object names in findings
	// (functions, relations in plans) are always schema-qualified.
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '120s'; SET LOCAL search_path = pg_catalog"); err != nil {
		return nil, err
	}

	s := &pgState{ctx: ctx, tx: tx, opts: opts, roles: map[uint32]*pgRole{}, internal: opts.internal()}
	if cls != nil {
		s.cls = cls.Index()
	}
	s.report = &Report{Role: role, Engine: "postgres"}
	if err := tx.QueryRow(ctx, "SELECT current_setting('server_version'), current_setting('server_version_num')::int, current_database()").
		Scan(&s.report.Version, &s.version, &s.report.Database); err != nil {
		return nil, err
	}
	if s.version < 130000 {
		return nil, fmt.Errorf("PostgreSQL %s is not supported; need 13 or later", s.report.Version)
	}
	steps := []func() error{
		func() error { return s.loadRoles(role) },
		s.roleFindings,
		s.columnFindings,
		s.viewFindings,
		s.functionFindings,
		s.foreignServerFindings,
		s.defaultPrivilegeFindings,
		s.keyAndReplicationFindings,
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

func (s *pgState) add(f Finding) { s.report.Findings = append(s.report.Findings, f) }

func (s *pgState) roleOIDs() []uint32 { return s.order }

func (s *pgState) schemas() []string {
	if s.opts.Schemas == nil {
		return []string{}
	}
	return s.opts.Schemas
}

// scopeSQL restricts a pg_namespace alias to user schemas in scope.
func scopeSQL(nsp string, param int) string {
	return fmt.Sprintf(`%[1]s.nspname NOT IN ('pg_catalog', 'information_schema')
		AND %[1]s.nspname NOT LIKE 'pg\_toast%%' AND %[1]s.nspname NOT LIKE 'pg\_temp\_%%'
		AND (coalesce(cardinality($%[2]d::text[]), 0) = 0 OR %[1]s.nspname = ANY($%[2]d::text[]))`, nsp, param)
}

// loadRoles finds every role the target can act as. Before PostgreSQL 16 a
// member can always SET ROLE to a granted role, and inherits its privileges
// unless the member is NOINHERIT. From 16 each grant carries its own INHERIT
// and SET options. A path that grants neither is unusable and skipped.
func (s *pgState) loadRoles(role string) error {
	err := s.tx.QueryRow(s.ctx, "SELECT oid FROM pg_roles WHERE rolname = $1", role).Scan(&s.self)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("role %q does not exist", role)
	} else if err != nil {
		return err
	}
	edge := `(SELECT rolinherit FROM pg_roles WHERE oid = m.member)`
	usable := `true`
	if s.version >= 160000 {
		edge, usable = `m.inherit_option`, `(m.inherit_option OR m.set_option)`
	}
	q := fmt.Sprintf(`
		WITH RECURSIVE r(oid, path, inherited) AS (
			SELECT $1::oid, ARRAY[$1::oid], true
			UNION ALL
			SELECT m.roleid, r.path || m.roleid, r.inherited AND %s
			FROM pg_auth_members m JOIN r ON m.member = r.oid
			WHERE %s AND m.roleid <> ALL (r.path)
		)
		SELECT DISTINCT ON (r.oid) r.oid, ro.rolname, r.inherited,
			(SELECT string_agg(x.rolname, ' > ' ORDER BY u.i) FROM unnest(r.path) WITH ORDINALITY u(o, i) JOIN pg_roles x ON x.oid = u.o),
			ro.rolsuper, ro.rolcreaterole, ro.rolbypassrls, ro.rolreplication
		FROM r JOIN pg_roles ro ON ro.oid = r.oid
		ORDER BY r.oid, r.inherited DESC, cardinality(r.path)`, edge, usable)
	rows, err := s.tx.Query(s.ctx, q, s.self)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r := &pgRole{}
		if err := rows.Scan(&r.oid, &r.name, &r.inherited, &r.chain, &r.super, &r.createrole, &r.bypassrls, &r.repl); err != nil {
			return err
		}
		s.roles[r.oid] = r
		if r.oid == s.self {
			s.order = append([]uint32{r.oid}, s.order...)
		} else {
			s.order = append(s.order, r.oid)
		}
	}
	return rows.Err()
}

// via describes how the target reaches role r.
func (s *pgState) via(r *pgRole) string {
	if r.oid == s.self {
		return ""
	}
	if r.inherited {
		return fmt.Sprintf(" (inherited: %s)", r.chain)
	}
	return fmt.Sprintf(" (by SET ROLE: %s)", r.chain)
}

func (s *pgState) reachable(name string) *pgRole {
	for _, oid := range s.order {
		if s.roles[oid].name == name {
			return s.roles[oid]
		}
	}
	return nil
}

// managedAdminRoles are the administrator roles of managed services. They
// are not superusers, but hold enough (CREATEROLE, membership in predefined
// roles, ownership) that the report does not try to trace them.
var managedAdminRoles = []string{"rds_superuser", "cloudsqlsuperuser", "azure_pg_admin", "alloydbsuperuser"}

func (s *pgState) roleFindings() error {
	for _, name := range []string{"pg_read_server_files", "pg_execute_server_program", "pg_write_server_files"} {
		if r := s.reachable(name); r != nil {
			s.add(Finding{Status: Unknown, Object: "role", Path: fmt.Sprintf("member of %s%s: can read or write server files or run programs, which bypasses table privileges", name, s.via(r))})
		}
	}
	for _, name := range managedAdminRoles {
		if r := s.reachable(name); r != nil {
			s.add(Finding{Status: Unknown, Object: "role", Path: fmt.Sprintf("member of %s%s: the managed service's administrator role", name, s.via(r))})
		}
	}
	for _, name := range []string{"pg_read_all_stats", "pg_monitor"} {
		if r := s.reachable(name); r != nil {
			s.add(Finding{Status: Warn, Object: "role", Path: fmt.Sprintf("member of %s%s: sees the query text of every session (pg_stat_activity, pg_stat_statements), including literal values in them", name, s.via(r))})
		}
	}
	for _, oid := range s.order {
		r := s.roles[oid]
		if r.repl && !r.super {
			s.add(Finding{Status: Unknown, Object: "role", Path: fmt.Sprintf("REPLICATION on %s%s: can stream a copy of the whole cluster (pg_basebackup) if pg_hba.conf allows replication connections, bypassing table privileges", r.name, s.via(r))})
		}
	}
	for _, oid := range s.order {
		r := s.roles[oid]
		if !r.createrole || r.super {
			continue
		}
		if s.version < 160000 {
			s.add(Finding{Status: Unknown, Object: "role", Path: fmt.Sprintf("CREATEROLE on %s%s: before PostgreSQL 16 it can grant itself any non-superuser role, including pg_read_all_data", r.name, s.via(r))})
		} else {
			s.add(Finding{Status: Warn, Object: "role", Path: fmt.Sprintf("CREATEROLE on %s%s: can create roles and grant roles it holds with ADMIN OPTION", r.name, s.via(r))})
		}
	}
	var rls bool
	if err := s.tx.QueryRow(s.ctx, `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relrowsecurity AND `+scopeSQL("n", 1)+`)`, s.schemas()).Scan(&rls); err != nil {
		return err
	}
	for _, oid := range s.order {
		if r := s.roles[oid]; r.bypassrls && !r.super && rls {
			s.add(Finding{Status: Warn, Object: "role", Path: fmt.Sprintf("BYPASSRLS on %s%s: row-level security policies in scope do not apply", r.name, s.via(r))})
		}
	}
	return nil
}

// relation is a readable column of a table or view, with what explains it.
type relation struct {
	schema, rel, col string
	owner            uint32
	readers          []uint32
	tblGrantees      []uint32
	colGrantees      []uint32
}

// explain lists the privilege paths by which the target reads a column. The
// server has already decided the column is readable; this only names why.
func (s *pgState) explain(r relation) string {
	var reasons []string
	seen := map[string]bool{}
	addReason := func(x string) {
		if !seen[x] {
			seen[x] = true
			reasons = append(reasons, x)
		}
	}
	in := func(oid uint32, list []uint32) bool {
		for _, x := range list {
			if x == oid {
				return true
			}
		}
		return false
	}
	for _, oid := range r.readers {
		role := s.roles[oid]
		if role == nil {
			continue
		}
		v := s.via(role)
		switch {
		case role.super:
			addReason("superuser " + role.name + v)
		case r.owner == oid:
			addReason("owner " + role.name + v)
		case in(oid, r.colGrantees):
			addReason("SELECT on column granted to " + role.name + v)
		case in(oid, r.tblGrantees):
			addReason("SELECT granted to " + role.name + v)
		case role.name == "pg_read_all_data":
			addReason("pg_read_all_data" + v)
		}
	}
	if in(0, r.tblGrantees) || in(0, r.colGrantees) {
		addReason("SELECT granted to PUBLIC")
	}
	if len(reasons) == 0 {
		return "readable; the server allows SELECT but the path was not identified"
	}
	return strings.Join(reasons, "; ")
}

func (s *pgState) label(schema, rel, col string) (classification.Column, bool) {
	if root, ok := s.roots[[2]string{schema, rel}]; ok {
		rel = root
	}
	c, ok := s.cls[classification.Key{Schema: schema, Table: rel, Column: col}]
	return c, ok
}

const readersSQL = `ARRAY(SELECT r FROM unnest($1::oid[]) r
	WHERE has_schema_privilege(r, n.oid, 'USAGE') AND has_column_privilege(r, c.oid, a.attnum, 'SELECT'))`

const granteesSQL = `
	ARRAY(SELECT DISTINCT e.grantee FROM aclexplode(c.relacl) e WHERE e.privilege_type = 'SELECT'),
	ARRAY(SELECT DISTINCT e.grantee FROM aclexplode(a.attacl) e WHERE e.privilege_type = 'SELECT')`

// columnFindings covers tables, partitions, materialized views and foreign
// tables: every column the target or a reachable role can SELECT.
func (s *pgState) columnFindings() error {
	s.roots = map[[2]string]string{}
	q := `SELECT n.nspname, c.relname, a.attname, c.relowner,
			CASE WHEN c.relispartition THEN (SELECT x.relname FROM pg_class x WHERE x.oid = pg_partition_root(c.oid)) END,
			` + readersSQL + `, ` + granteesSQL + `
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'm', 'f')
			AND n.nspname <> $3 AND ` + scopeSQL("n", 2) + `
		ORDER BY 1, 2, a.attnum`
	rows, err := s.tx.Query(s.ctx, q, s.roleOIDs(), s.schemas(), s.internal)
	if err != nil {
		return err
	}
	var rels []relation
	for rows.Next() {
		var r relation
		var root *string
		if err := rows.Scan(&r.schema, &r.rel, &r.col, &r.owner, &root, &r.readers, &r.tblGrantees, &r.colGrantees); err != nil {
			rows.Close()
			return err
		}
		if root != nil {
			s.roots[[2]string{r.schema, r.rel}] = *root
		}
		if len(r.readers) > 0 {
			rels = append(rels, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range rels {
		obj := r.schema + "." + r.rel + "." + r.col
		c, ok := s.label(r.schema, r.rel, r.col)
		switch {
		case !ok:
			s.add(Finding{Status: Unlabeled, Object: obj, Path: "readable raw; not in the classification, scan again: " + s.explain(r)})
		case c.IsPII() && c.DerivedFrom != "":
			s.add(Finding{Status: Unknown, Object: obj, Label: c.Label, Path: derivedPath(r.schema, r.rel, c) + ": " + s.explain(r)})
		case c.IsPII():
			s.add(Finding{Status: Raw, Object: obj, Label: c.Label, Path: s.explain(r)})
		}
	}
	return nil
}

var (
	refRe = regexp.MustCompile(`("(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)\.("(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`)
	// String literals are removed before looking for column references.
	literalRe = regexp.MustCompile(`'(?:[^']|'')*'`)
	// Whole-row references (row_to_json(c.*)) read every column at once.
	wholeRowRe = regexp.MustCompile(`("(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)\.\*`)
	// Parameters and subplans carry values computed elsewhere in the plan.
	paramRe = regexp.MustCompile(`\$\d|InitPlan|SubPlan`)
)

func unquote(id string) string {
	if strings.HasPrefix(id, `"`) && strings.HasSuffix(id, `"`) && len(id) >= 2 {
		return strings.ReplaceAll(id[1:len(id)-1], `""`, `"`)
	}
	return id
}

type colRef struct {
	raw            string
	alias          string // the relation alias in the plan
	schema, rel    string
	col            string
	resolved       bool
	label          classification.Column
	labeled, isPII bool
}

// planNode is one node of EXPLAIN (FORMAT JSON).
type planNode struct {
	NodeType     string     `json:"Node Type"`
	RelationName string     `json:"Relation Name"`
	Schema       string     `json:"Schema"`
	Alias        string     `json:"Alias"`
	Output       []string   `json:"Output"`
	Plans        []planNode `json:"Plans"`
}

// explainJSON returns the plan of query as canonical JSON (for comparing
// plans) and as a tree. It runs in a savepoint so that a failing EXPLAIN
// does not abort the report.
func (s *pgState) explainJSON(query string) (string, *planNode, error) {
	sp, err := s.tx.Begin(s.ctx)
	if err != nil {
		return "", nil, err
	}
	defer sp.Rollback(s.ctx)
	var raw []byte
	if err := sp.QueryRow(s.ctx, "EXPLAIN (VERBOSE, COSTS OFF, FORMAT JSON) "+query).Scan(&raw); err != nil {
		return "", nil, err
	}
	var generic any
	var tree []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", nil, err
	}
	if err := json.Unmarshal(raw, &tree); err != nil {
		return "", nil, err
	}
	if len(tree) != 1 {
		return "", nil, fmt.Errorf("EXPLAIN returned %d plans", len(tree))
	}
	// Only the plan tree: the rest differs between queries with the same
	// plan (Query Identifier, shown when compute_query_id is on, as it is
	// wherever pg_stat_statements is loaded).
	arr, ok := generic.([]any)
	if !ok || len(arr) != 1 {
		return "", nil, fmt.Errorf("unexpected EXPLAIN output")
	}
	top, ok := arr[0].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("unexpected EXPLAIN output")
	}
	canon, err := json.Marshal(top["Plan"]) // map keys sorted
	if err != nil {
		return "", nil, err
	}
	return string(canon), &tree[0].Plan, nil
}

// viewPlan is the plan of SELECT col FROM view.
type viewPlan struct {
	canon    string
	output   string   // top-level output expression
	refs     []colRef // column references in output
	readsKey bool     // the plan reads the maskplan key table
	// untraceable says why the output cannot be traced to base columns, if
	// it cannot.
	untraceable string
}

// lineage traces one view column to base columns using the plan. It traces
// only what it fully understands: one output expression whose column
// references each name a base relation scanned exactly once under that
// alias. Parameters, subplans, whole-row references, CTE, subquery and
// function scans, and nodes without an output list make it untraceable.
func (s *pgState) lineage(schema, view, col string) (*viewPlan, error) {
	canon, root, err := s.explainJSON(fmt.Sprintf("SELECT %s FROM %s",
		pgx.Identifier{col}.Sanitize(), pgx.Identifier{schema, view}.Sanitize()))
	if err != nil {
		return nil, err
	}
	p := &viewPlan{canon: canon}
	type rel struct{ schema, name string }
	aliases := map[string][]rel{}
	var walk func(n *planNode)
	walk = func(n *planNode) {
		if n.Alias != "" {
			aliases[n.Alias] = append(aliases[n.Alias], rel{n.Schema, n.RelationName})
		}
		if n.Schema == s.internal && n.RelationName == "key_material" {
			p.readsKey = true
		}
		for i := range n.Plans {
			walk(&n.Plans[i])
		}
	}
	walk(root)
	if len(root.Output) != 1 {
		p.untraceable = fmt.Sprintf("the top plan node (%s) has %d output expressions", root.NodeType, len(root.Output))
		return p, nil
	}
	p.output = root.Output[0]
	stripped := literalRe.ReplaceAllString(p.output, "''")
	switch {
	case wholeRowRe.MatchString(stripped):
		p.untraceable = "whole-row reference"
	case paramRe.MatchString(stripped):
		p.untraceable = "value computed by a subquery"
	}
	for _, m := range refRe.FindAllStringSubmatch(stripped, -1) {
		r := colRef{raw: m[0], alias: unquote(m[1]), col: unquote(m[2])}
		if base := aliases[r.alias]; len(base) == 1 && base[0].name != "" {
			r.schema, r.rel, r.resolved = base[0].schema, base[0].name, true
			r.label, r.labeled = s.label(r.schema, r.rel, r.col)
			r.isPII = r.labeled && r.label.IsPII()
		}
		p.refs = append(p.refs, r)
	}
	return p, nil
}

var (
	// The label and kept length of a deparsed Postgres token expression.
	tokenLabelRe = regexp.MustCompile(`'([a-z0-9_.]+):'::text`)
	// PostgreSQL 14 and later deparse substring(x from 1 for n) in SQL
	// syntax, 13 as a function call: "substring"(x, 1, n). The length only
	// chooses which reference token to build; the plan comparison decides.
	tokenLenRe = regexp.MustCompile(`(?:FROM 1 FOR |, 1, )(\d+)\), 'hex'::text\)`)
)

// isMaskplanToken reports whether the view column is exactly a maskplan
// token of its one base column. Looking for the token's shape is not enough:
// coalesce(email, <token>) has the shape and returns raw emails. So the
// report builds the token expression maskplan would generate for that base
// column, has the server plan it, and requires the two plans to be
// identical, key-table InitPlans included. Anything else,
// including correct masking written another way, is not recognized and is
// reported UNKNOWN.
func (s *pgState) isMaskplanToken(v *viewPlan) (bool, error) {
	if !v.readsKey || !singleColumn(v.refs) {
		return false, nil
	}
	ref := v.refs[0]
	lm := tokenLabelRe.FindStringSubmatch(v.output)
	nm := tokenLenRe.FindStringSubmatch(v.output)
	if lm == nil || nm == nil {
		return false, nil
	}
	var n int
	if _, err := fmt.Sscanf(nm[1], "%d", &n); err != nil {
		return false, nil
	}
	_, pads, err := sqlexpr.KeySource(sqlexpr.Postgres, pgx.Identifier{s.internal, "key_material"}.Sanitize(), "k")
	if err != nil {
		return false, err
	}
	for _, norm := range []token.Normalizer{token.Email, token.Phone, token.Trim} {
		expr, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{
			Expr:        pgx.Identifier{ref.alias, ref.col}.Sanitize(),
			Label:       lm[1],
			Normalizer:  norm,
			TokenHexLen: 2 * n,
		}, pads)
		if err != nil {
			return false, nil // not a label or length maskplan generates
		}
		want, _, err := s.explainJSON(fmt.Sprintf("SELECT %s FROM %s %s", expr,
			pgx.Identifier{ref.schema, ref.rel}.Sanitize(), pgx.Identifier{ref.alias}.Sanitize()))
		if err == nil && want == v.canon {
			return true, nil
		}
	}
	return false, nil
}

// singleColumn reports whether refs are all the same resolved column. A
// token can reference its column more than once (the phone normalizer does).
func singleColumn(refs []colRef) bool {
	if len(refs) == 0 || !refs[0].resolved {
		return false
	}
	for _, r := range refs[1:] {
		if r.alias != refs[0].alias || r.col != refs[0].col {
			return false
		}
	}
	return true
}

func trimParens(s string) string {
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func (s *pgState) viewFindings() error {
	q := `SELECT n.nspname, c.relname, a.attname, c.relowner, ` + readersSQL + `, ` + granteesSQL + `,
			(SELECT e.extname FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
					AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e')
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind = 'v' AND n.nspname <> $3 AND ` + scopeSQL("n", 2) + `
		ORDER BY 1, 2, a.attnum`
	rows, err := s.tx.Query(s.ctx, q, s.roleOIDs(), s.schemas(), s.internal)
	if err != nil {
		return err
	}
	var views []relation
	extViews := map[[2]string]bool{}
	for rows.Next() {
		var r relation
		var ext *string
		if err := rows.Scan(&r.schema, &r.rel, &r.col, &r.owner, &r.readers, &r.tblGrantees, &r.colGrantees, &ext); err != nil {
			rows.Close()
			return err
		}
		if len(r.readers) == 0 {
			continue
		}
		// Views that belong to an extension (pg_stat_statements, PostGIS's
		// geometry_columns) read catalogs or extension functions, not
		// application data. Tracing them would fail every role on most
		// managed services; they get one WARN each instead.
		if ext != nil {
			if k := [2]string{r.schema, r.rel}; !extViews[k] {
				extViews[k] = true
				s.add(Finding{Status: Warn, Object: "view " + r.schema + "." + r.rel,
					Path: "from extension " + *ext + ": extension views are not traced; view: " + s.explain(r)})
			}
			continue
		}
		views = append(views, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, v := range views {
		obj := v.schema + "." + v.rel + "." + v.col
		access := "view: " + s.explain(v)
		p, err := s.lineage(v.schema, v.rel, v.col)
		if err != nil {
			s.add(Finding{Status: Unknown, Object: obj, Path: fmt.Sprintf("cannot trace view column (EXPLAIN failed: %v); %s", err, access)})
			continue
		}
		expr, refs := p.output, p.refs
		var pii, unlabeled []colRef
		unresolved := false
		for _, r := range refs {
			switch {
			case !r.resolved:
				unresolved = true
			case r.isPII:
				pii = append(pii, r)
			case !r.labeled:
				unlabeled = append(unlabeled, r)
			}
		}
		short := strings.Join(strings.Fields(expr), " ")
		if len(short) > 120 {
			short = short[:117] + "..."
		}
		passthrough := len(pii) == 1 && len(refs) == 1 && trimParens(expr) == pii[0].raw
		masked := false
		if !passthrough && singleColumn(refs) {
			if masked, err = s.isMaskplanToken(p); err != nil {
				return err
			}
		}
		switch {
		case passthrough && pii[0].label.DerivedFrom != "":
			s.add(Finding{Status: Unknown, Object: obj, Label: pii[0].label.Label, Path: "passes through " + derivedPath(pii[0].schema, pii[0].rel, pii[0].label) + "; " + access})
		case passthrough:
			base := pii[0].schema + "." + pii[0].rel + "." + pii[0].col
			s.add(Finding{Status: Raw, Object: obj, Label: pii[0].label.Label, Path: "passes through " + base + "; " + access})
		case masked:
			r := refs[0]
			s.add(Finding{Status: Masked, Object: obj, Label: r.label.Label, Path: "maskplan token of " + r.schema + "." + r.rel + "." + r.col})
		case len(pii) > 0:
			s.add(Finding{Status: Unknown, Object: obj, Label: pii[0].label.Label, Path: "expression over " + pii[0].schema + "." + pii[0].rel + "." + pii[0].col + " is not a maskplan token: " + short + "; " + access})
		case p.untraceable != "":
			s.add(Finding{Status: Unknown, Object: obj, Path: "cannot trace view column to base columns (" + p.untraceable + "): " + short + "; " + access})
		case unresolved:
			s.add(Finding{Status: Unknown, Object: obj, Path: "cannot trace view column to base columns: " + short + "; " + access})
		case len(unlabeled) > 0:
			s.add(Finding{Status: Unlabeled, Object: obj, Path: "exposes " + unlabeled[0].schema + "." + unlabeled[0].rel + "." + unlabeled[0].col + ", which is not in the classification; " + access})
		}
	}
	return nil
}

// derivedPath explains a materialized token column. Its values are tokens
// only if whatever writes them computes tokens; until the report can verify
// that (the trigger maskplan apply will create), it is not MASKED.
func derivedPath(schema, rel string, c classification.Column) string {
	return fmt.Sprintf("%s.%s.%s is classified as the token column of %s, but what fills it is not verified", schema, rel, c.Column, c.DerivedFrom)
}

// labeledColumns returns the PII-labeled columns as parallel arrays.
func (s *pgState) labeledColumns() (schemas, tables, cols []string) {
	for k, c := range s.cls {
		if c.IsPII() {
			schemas, tables, cols = append(schemas, k.Schema), append(tables, k.Table), append(cols, k.Column)
		}
	}
	return
}

// functionFindings flags SECURITY DEFINER functions the target can execute
// whose owner can read labeled columns raw: calling one runs with the owner's
// rights, which the report cannot see through. User-defined ones are
// UNKNOWN. Functions that belong to an extension are WARN, naming the
// extension: on managed services extensions are owned by the admin role,
// which can read everything, so UNKNOWN would fail every role there.
func (s *pgState) functionFindings() error {
	sch, tbl, col := s.labeledColumns()
	q := `SELECT p.oid::regprocedure::text, o.rolname,
			ARRAY(SELECT r FROM unnest($1::oid[]) r WHERE has_function_privilege(r, p.oid, 'EXECUTE')),
			(SELECT count(*) FROM unnest($3::text[], $4::text[], $5::text[]) AS l(s, t, c)
				JOIN pg_namespace ln ON ln.nspname = l.s
				JOIN pg_class lc ON lc.relnamespace = ln.oid AND lc.relname = l.t
				JOIN pg_attribute la ON la.attrelid = lc.oid AND la.attname = l.c
				WHERE has_column_privilege(p.proowner, lc.oid, la.attnum, 'SELECT')),
			(SELECT e.extname FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
					AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e')
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles o ON o.oid = p.proowner
		WHERE p.prosecdef AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype) AND ` + scopeSQL("n", 2)
	rows, err := s.tx.Query(s.ctx, q, s.roleOIDs(), s.schemas(), sch, tbl, col)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sig, owner string
		var execs []uint32
		var n int
		var ext *string
		if err := rows.Scan(&sig, &owner, &execs, &n, &ext); err != nil {
			return err
		}
		if len(execs) == 0 || n == 0 {
			continue
		}
		r := s.roles[execs[0]]
		path := fmt.Sprintf("SECURITY DEFINER, runs as %s, who can read %d labeled columns raw; executable by %s%s", owner, n, r.name, s.via(r))
		if ext != nil {
			s.add(Finding{Status: Warn, Object: "function " + sig, Path: "from extension " + *ext + ": " + path + "; extension functions are not traced"})
			continue
		}
		s.add(Finding{Status: Unknown, Object: "function " + sig, Path: path})
	}
	return rows.Err()
}

func (s *pgState) foreignServerFindings() error {
	rows, err := s.tx.Query(s.ctx, `SELECT srvname, CASE WHEN umuser = 0 THEN 'PUBLIC' ELSE usename END
		FROM pg_user_mappings WHERE umuser = 0 OR umuser = ANY($1::oid[]) ORDER BY 1, 2`, s.roleOIDs())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var srv, user string
		if err := rows.Scan(&srv, &user); err != nil {
			return err
		}
		s.add(Finding{Status: Unknown, Object: "foreign server " + srv,
			Path: "user mapping for " + user + ": queries run on the remote server as the mapped user, outside this database's privileges"})
	}
	return rows.Err()
}

func (s *pgState) defaultPrivilegeFindings() error {
	rows, err := s.tx.Query(s.ctx, `SELECT pg_get_userbyid(d.defaclrole), coalesce(n.nspname, ''),
			CASE WHEN e.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(e.grantee) END
		FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace, aclexplode(d.defaclacl) e
		WHERE d.defaclobjtype = 'r' AND e.privilege_type = 'SELECT' AND (e.grantee = 0 OR e.grantee = ANY($1::oid[]))
			AND (n.oid IS NULL OR coalesce(cardinality($2::text[]), 0) = 0 OR n.nspname = ANY($2::text[]))
		ORDER BY 1, 2, 3`, s.roleOIDs(), s.schemas())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var creator, schema, grantee string
		if err := rows.Scan(&creator, &schema, &grantee); err != nil {
			return err
		}
		where := "in schema " + schema
		if schema == "" {
			where = "in every schema"
		}
		s.add(Finding{Status: Warn, Object: "default privileges " + where,
			Path: fmt.Sprintf("tables %s creates %s will be readable by %s, including any personal data added later", creator, where, grantee)})
	}
	return rows.Err()
}

func (s *pgState) keyAndReplicationFindings() error {
	keyTable := pgx.Identifier{s.internal, "key_material"}.Sanitize()
	var exists bool
	if err := s.tx.QueryRow(s.ctx, "SELECT to_regclass($1) IS NOT NULL", keyTable).Scan(&exists); err != nil {
		return err
	}
	if exists {
		rows, err := s.tx.Query(s.ctx, `SELECT r FROM unnest($1::oid[]) r
			WHERE has_schema_privilege(r, $2::text, 'USAGE') AND has_any_column_privilege(r, to_regclass($3), 'SELECT')`,
			s.roleOIDs(), s.internal, keyTable)
		if err != nil {
			return err
		}
		var readers []uint32
		for rows.Next() {
			var oid uint32
			if err := rows.Scan(&oid); err != nil {
				rows.Close()
				return err
			}
			readers = append(readers, oid)
		}
		rows.Close()
		for _, oid := range readers {
			r := s.roles[oid]
			s.add(Finding{Status: Key, Object: s.internal + ".key_material", Path: "can read the token key material as " + r.name + s.via(r) + "; every token can be reversed by guessing"})
		}
		sp, err := s.tx.Begin(s.ctx)
		if err != nil {
			return err
		}
		var n int
		if err := sp.QueryRow(s.ctx, "SELECT count(*) FROM "+keyTable).Scan(&n); err != nil {
			s.add(Finding{Status: Warn, Object: s.internal + ".key_material", Path: "cannot count key rows as the inspecting user: " + err.Error()})
		} else if n != 1 {
			s.add(Finding{Status: Warn, Object: s.internal + ".key_material", Path: fmt.Sprintf("has %d rows, want exactly 1: with none, every token is NULL", n)})
		}
		if n > 0 {
			if err := s.keyLiteralFindings(sp, keyTable); err != nil {
				return err
			}
		}
		sp.Rollback(s.ctx)
	}
	rows, err := s.tx.Query(s.ctx, `SELECT pubname, 'FOR ALL TABLES' FROM pg_publication WHERE puballtables
		UNION SELECT DISTINCT pubname, 'includes ' || schemaname || '.' || tablename FROM pg_publication_tables WHERE schemaname = $1
		ORDER BY 1`, s.internal)
	if err != nil {
		return err
	}
	for rows.Next() {
		var pub, what string
		if err := rows.Scan(&pub, &what); err != nil {
			rows.Close()
			return err
		}
		s.add(Finding{Status: Warn, Object: "publication " + pub, Path: what + ": the key table can leave the database through logical replication"})
	}
	rows.Close()
	var largeObjects bool
	if err := s.tx.QueryRow(s.ctx, "SELECT EXISTS (SELECT 1 FROM pg_largeobject_metadata)").Scan(&largeObjects); err != nil {
		return err
	}
	if largeObjects {
		s.add(Finding{Status: Warn, Object: "large objects", Path: "the database holds large objects; their contents are not classified and their privileges are not checked"})
	}
	var standby bool
	if err := s.tx.QueryRow(s.ctx, "SELECT pg_is_in_recovery()").Scan(&standby); err != nil {
		return err
	}
	if standby {
		s.add(Finding{Status: Warn, Object: "connection", Path: "connected to a standby: grants and the key table come from the primary; check the primary too"})
	}
	return nil
}

// keyLiteralFindings looks for the key pads written into a view or function
// definition. Definitions are readable by every role through pg_views and
// pg_proc, so a literal key there is a key every role holds. Only the hex
// spelling ('\x...'::bytea, decode(..., 'hex')) is recognized.
func (s *pgState) keyLiteralFindings(tx pgx.Tx, keyTable string) error {
	rows, err := tx.Query(s.ctx, `WITH k AS (SELECT encode(ipad, 'hex') AS i, encode(opad, 'hex') AS o FROM `+keyTable+`)
		SELECT 'view ' || quote_ident(n.nspname) || '.' || quote_ident(c.relname)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, k
		WHERE c.relkind IN ('v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			AND (strpos(lower(pg_get_viewdef(c.oid)), k.i) > 0 OR strpos(lower(pg_get_viewdef(c.oid)), k.o) > 0)
		UNION
		SELECT 'function ' || p.oid::regprocedure::text FROM pg_proc p, k
		WHERE strpos(lower(p.prosrc), k.i) > 0 OR strpos(lower(p.prosrc), k.o) > 0
		ORDER BY 1`)
	if err != nil {
		return err
	}
	objs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, o := range objs {
		s.add(Finding{Status: Key, Object: o, Path: "its definition contains the token key material in hex, and definitions are readable by every role"})
	}
	return nil
}

func (s *pgState) settings() error {
	st := &s.report.Settings
	var canLogin bool
	var connLimit int
	if err := s.tx.QueryRow(s.ctx, "SELECT rolcanlogin, rolconnlimit FROM pg_roles WHERE oid = $1", s.self).Scan(&canLogin, &connLimit); err != nil {
		return err
	}
	switch {
	case !canLogin:
		st.Login = "cannot log in (NOLOGIN); reachable only through other roles"
	case s.reachable("rds_iam") != nil:
		st.Login = "IAM token (rds_iam)"
	case s.reachable("cloudsqliamuser") != nil || s.reachable("cloudsqliamserviceaccount") != nil:
		st.Login = "IAM (Cloud SQL)"
	default:
		st.Login = "password or certificate"
		if sp, err := s.tx.Begin(s.ctx); err == nil {
			var hasPassword bool
			if err := sp.QueryRow(s.ctx, "SELECT rolpassword IS NOT NULL FROM pg_authid WHERE oid = $1", s.self).Scan(&hasPassword); err == nil {
				st.Login = "password"
				if !hasPassword {
					st.Login = "no password set (certificate, trust or peer authentication)"
				}
			}
			sp.Rollback(s.ctx)
		}
	}
	if connLimit < 0 {
		st.ConnectionLimit = "none"
	} else {
		st.ConnectionLimit = fmt.Sprintf("%d (enforced)", connLimit)
	}
	roleSetting := func(name string) (string, error) {
		var v *string
		err := s.tx.QueryRow(s.ctx, `SELECT split_part(c, '=', 2) FROM pg_db_role_setting d, unnest(d.setconfig) c
			WHERE d.setrole = $1 AND d.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
				AND split_part(c, '=', 1) = $2
			ORDER BY d.setdatabase DESC LIMIT 1`, s.self, name).Scan(&v)
		if errors.Is(err, pgx.ErrNoRows) || v == nil {
			return "", nil
		}
		return *v, err
	}
	audit, err := roleSetting("pgaudit.log")
	if err != nil {
		return err
	}
	switch {
	case audit != "" && audit != "none":
		st.Audit = "pgaudit.log = " + audit + " (role setting)"
	default:
		var global *string
		if err := s.tx.QueryRow(s.ctx, "SELECT current_setting('pgaudit.log', true)").Scan(&global); err != nil {
			return err
		}
		if global != nil && *global != "" && *global != "none" {
			st.Audit = "pgaudit.log = " + *global + " (server or database setting)"
		} else {
			st.Audit = "none: reads by this role are not logged"
		}
	}
	timeout, err := roleSetting("statement_timeout")
	if err != nil {
		return err
	}
	if timeout == "" {
		st.StatementTimeout = "none"
	} else {
		st.StatementTimeout = timeout + " (advisory: the session can override it)"
	}
	return nil
}
