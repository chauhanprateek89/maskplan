package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
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
	// Policy, if set, is checked: the role's views must be the ones it
	// compiles to for Source (default: its only source of this engine).
	Policy *policy.Policy
	Source string
	// AsRole plans view columns as the reported role (SET ROLE), not as
	// the inspecting user; the inspecting user must be able to SET ROLE to
	// it. Postgres only.
	AsRole bool
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
	roots    map[[2]string][2]string // schema, partition -> schema, root table
	internal string
	catalogs map[string]bool   // system catalog relation -> PUBLIC can read it
	wheres   map[string]string // view -> top-level WHERE clause
	filtered map[string]bool   // views read through a Subquery Scan
	read     map[string]bool   // views the role can read
	matched  map[string]bool   // views that are the policy's
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

	if opts.Policy != nil {
		if opts.Source, err = PolicySource(opts.Policy, "postgres", opts.Source); err != nil {
			return nil, err
		}
	}
	if opts.AsRole {
		var can bool
		if err := tx.QueryRow(ctx, "SELECT pg_has_role(current_user, $1, 'MEMBER')", role).Scan(&can); err != nil {
			return nil, err
		}
		if !can {
			return nil, fmt.Errorf("--as-role: %s cannot SET ROLE to %s; run as a superuser or a member of it", "the inspecting user", role)
		}
	}
	s := &pgState{ctx: ctx, tx: tx, opts: opts, roles: map[uint32]*pgRole{}, internal: opts.internal(), catalogs: map[string]bool{}, wheres: map[string]string{}, filtered: map[string]bool{}, read: map[string]bool{}, matched: map[string]bool{}}
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
		s.policyFindings,
		s.conditionFindings,
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
	// A partition is classified under its root, which may live in another
	// schema (GitLab keeps partitions in gitlab_partitions_static).
	if root, ok := s.roots[[2]string{schema, rel}]; ok {
		schema, rel = root[0], root[1]
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
	s.roots = map[[2]string][2]string{}
	q := `SELECT n.nspname, c.relname, a.attname, c.relowner,
			CASE WHEN c.relispartition THEN (SELECT ARRAY[xn.nspname::text, x.relname::text] FROM pg_class x
				JOIN pg_namespace xn ON xn.oid = x.relnamespace WHERE x.oid = pg_partition_root(c.oid)) END,
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
		var root []string
		if err := rows.Scan(&r.schema, &r.rel, &r.col, &r.owner, &root, &r.readers, &r.tblGrantees, &r.colGrantees); err != nil {
			rows.Close()
			return err
		}
		if len(root) == 2 {
			s.roots[[2]string{r.schema, r.rel}] = [2]string{root[0], root[1]}
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
	Relationship string     `json:"Parent Relationship"`
	RelationName string     `json:"Relation Name"`
	Schema       string     `json:"Schema"`
	Alias        string     `json:"Alias"`
	Output       []string   `json:"Output"`
	Plans        []planNode `json:"Plans"`
	// Conditions, which run on base rows whatever the query selects.
	Filter        string `json:"Filter"`
	JoinFilter    string `json:"Join Filter"`
	HashCond      string `json:"Hash Cond"`
	MergeCond     string `json:"Merge Cond"`
	IndexCond     string `json:"Index Cond"`
	RecheckCond   string `json:"Recheck Cond"`
	OneTimeFilter string `json:"One-Time Filter"`
	TIDCond       string `json:"TID Cond"`
}

func (n *planNode) conditions() []string {
	var out []string
	for _, c := range []string{n.Filter, n.JoinFilter, n.HashCond, n.MergeCond, n.IndexCond, n.RecheckCond, n.OneTimeFilter, n.TIDCond} {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// explainJSON returns the plan of query as canonical JSON (for comparing
// plans) and as a tree. It runs in a savepoint so that a failing EXPLAIN
// does not abort the report.
func (s *pgState) explainJSON(query string) (string, *planNode, error) {
	return s.explainAs(query, false)
}

// explainAs is explainJSON, run as the reported role when asRole is set
// and --as-role was given: then the plan has the role's own row-level
// security and, for security_invoker views, its own rights on the base
// tables. The savepoint's rollback resets the role.
func (s *pgState) explainAs(query string, asRole bool) (string, *planNode, error) {
	sp, err := s.tx.Begin(s.ctx)
	if err != nil {
		return "", nil, err
	}
	defer sp.Rollback(s.ctx)
	if asRole && s.opts.AsRole {
		if _, err := sp.Exec(s.ctx, "SET LOCAL ROLE "+pgx.Identifier{s.report.Role}.Sanitize()); err != nil {
			return "", nil, err
		}
	}
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
	canon, err := json.Marshal(canonicalPlan(top["Plan"])) // map keys sorted
	if err != nil {
		return "", nil, err
	}
	return string(canon), &tree[0].Plan, nil
}

// viewPlan is the plan of SELECT col FROM view.
type viewPlan struct {
	schema, view string
	canon        string
	output       string   // top-level output expression
	refs         []colRef // column references in output
	readsKey     bool     // the plan reads the maskplan key table
	rels         map[string][]rel
	// barrier is set when the view is not flattened (security_barrier):
	// the plan reads the column from a Subquery Scan.
	barrier *subqueryScan
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
	canon, root, err := s.explainAs(fmt.Sprintf("SELECT %s FROM %s",
		pgx.Identifier{col}.Sanitize(), pgx.Identifier{schema, view}.Sanitize()), true)
	if err != nil {
		return nil, err
	}
	p := &viewPlan{schema: schema, view: view, canon: canon}
	aliases := map[string][]rel{}
	p.rels = aliases
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
	partitioned := false
	if expr, ok := s.partitionMembers(root); ok {
		root, partitioned = &planNode{NodeType: root.NodeType, Output: []string{expr}}, true
	}
	if sq := barrierScan(root); sq != nil {
		p.barrier = sq
		root = &planNode{NodeType: root.NodeType, Output: []string{sq.expr}}
	}
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
			if root, ok := s.roots[[2]string{r.schema, r.rel}]; ok && partitioned {
				// Read through the root: findings and the reference name it.
				r.schema, r.rel = root[0], root[1]
			}
			r.label, r.labeled = s.label(r.schema, r.rel, r.col)
			r.isPII = r.labeled && r.label.IsPII()
			if !r.labeled && (r.schema == "pg_catalog" || r.schema == "information_schema") {
				// What PUBLIC can read in the catalog, a view exposes to no
				// one new. pg_authid and the like are another matter.
				public, err := s.publicCatalog(r.schema, r.rel)
				if err != nil {
					return nil, err
				}
				if public {
					r.labeled, r.label = true, classification.Column{Label: classification.None}
				} else if p.untraceable == "" {
					p.untraceable = "reads " + r.schema + "." + r.rel + ", which PUBLIC cannot read"
				}
			}
		}
		p.refs = append(p.refs, r)
	}
	return p, nil
}

type rel struct{ schema, name string }

// partitionMembers recognizes a column read from a partitioned table: an
// Append (or Merge Append) without an output list whose members each scan
// a partition of the same root table and compute the same expression,
// apart from their own alias. It returns the first member's expression;
// its alias resolves to a partition, which is labeled as its root. A UNION
// ALL of different tables, or of different expressions, is not this.
func (s *pgState) partitionMembers(n *planNode) (string, bool) {
	if (n.NodeType != "Append" && n.NodeType != "Merge Append") || len(n.Output) != 0 {
		return "", false
	}
	var first string
	var root [2]string
	members := 0
	for i := range n.Plans {
		m := &n.Plans[i]
		if m.Relationship != "Member" {
			continue
		}
		if m.RelationName == "" || m.Alias == "" || len(m.Output) != 1 {
			return "", false
		}
		r := [2]string{m.Schema, m.RelationName}
		if base, ok := s.roots[r]; ok {
			r = base
		}
		// The member's own alias, as a qualifier, made the same for all.
		expr := memberAliasRe(m.Alias).ReplaceAllString(literalRe.ReplaceAllString(m.Output[0], "''"), "${1}@.")
		if members == 0 {
			first, root = expr, r
		} else if expr != first || r != root {
			return "", false
		}
		members++
	}
	if members == 0 {
		return "", false
	}
	for i := range n.Plans {
		if n.Plans[i].Relationship == "Member" {
			return n.Plans[i].Output[0], true
		}
	}
	return "", false
}

// memberAliasRe matches alias used as a qualifier, quoted or not.
func memberAliasRe(alias string) *regexp.Regexp {
	q := regexp.QuoteMeta(alias)
	return regexp.MustCompile(`(^|[^A-Za-z0-9_$".])(?:` + q + `|"` + strings.ReplaceAll(q, `"`, `""`) + `")\.`)
}

// subqueryScan is a view column read through a Subquery Scan: a view that
// is not flattened, as security_barrier views are not.
type subqueryScan struct {
	alias, col string
	outputs    []string // the subquery's output list
	pos        int      // which of them the column is
	expr       string   // what the column is, or NULL if every output is NULL
	nested     bool     // through more than one Subquery Scan
}

var nullConstRe = regexp.MustCompile(`^NULL::(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_ ]*)(?:\.(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_]*))?(?:\(\d+(?:,\d+)?\))?(?:\[\])*$`)

// barrierScan recognizes SELECT col FROM view planned as a Subquery Scan
// whose only output is a plain reference to one subquery column, and
// follows it down through nested Subquery Scans. The planner replaces every
// subquery output the query does not use with a NULL constant, so the
// column is the one output that is not NULL. Which output that is comes
// from the plan, not from the view's column list: a view can name its
// subquery's columns in any order. Two non-NULL outputs (volatile
// expressions are never replaced) end the trace there, and the column
// cannot be traced. Only a single level is recognized as a masked view's
// shape; deeper ones are traced for raw columns only.
func barrierScan(root *planNode) *subqueryScan {
	if len(root.Output) != 1 {
		return nil
	}
	var first *subqueryScan
	n, expr := root, root.Output[0]
	for depth := 0; n.NodeType == "Subquery Scan" && len(n.Plans) == 1; depth++ {
		m := refRe.FindStringSubmatch(expr)
		if m == nil || m[0] != expr || unquote(m[1]) != n.Alias {
			break
		}
		sq := &subqueryScan{alias: n.Alias, col: unquote(m[2]), outputs: n.Plans[0].Output, pos: -1}
		for i, o := range sq.outputs {
			if !nullConstRe.MatchString(o) {
				if sq.pos >= 0 {
					return nil
				}
				sq.pos = i
			}
		}
		switch {
		case sq.pos >= 0:
			sq.expr = sq.outputs[sq.pos]
		case len(sq.outputs) > 0:
			sq.pos, sq.expr = 0, sq.outputs[0]
		default:
			return nil
		}
		if first == nil {
			first = sq
		} else {
			first.nested = true
		}
		first.expr = sq.expr
		n, expr = &n.Plans[0], sq.expr
	}
	return first
}

// publicCatalog reports whether PUBLIC can read a system catalog relation.
func (s *pgState) publicCatalog(schema, rel string) (bool, error) {
	k := schema + "." + rel
	if v, ok := s.catalogs[k]; ok {
		return v, nil
	}
	var v bool
	err := s.tx.QueryRow(s.ctx, `SELECT coalesce(has_table_privilege('public', to_regclass($1), 'SELECT'), false)`,
		pgx.Identifier{schema, rel}.Sanitize()).Scan(&v)
	s.catalogs[k] = v
	return v, err
}

var (
	// The label and kept length of a deparsed Postgres token expression.
	tokenLabelRe = regexp.MustCompile(`'([a-z0-9_.]+):'::text`)
	// PostgreSQL 14 and later deparse substring(x from 1 for n) in SQL
	// syntax, 13 as a function call: "substring"(x, 1, n). The length only
	// chooses which reference token to build; the plan comparison decides.
	tokenLenRe = regexp.MustCompile(`(?:FROM 1 FOR |, 1, )(\d+)\), 'hex'::text\)`)
)

// recognized is a view column that is exactly a maskplan transform of one
// base column.
type recognized struct {
	transform string
	base      colRef
}

var prefixLenRe = regexp.MustCompile(`^"left"\(.*, (\d+)\)$`)

// recognize reports whether the view column is exactly a maskplan transform
// of one base column. Looking for a transform's shape is not enough:
// coalesce(email, <token>) has the shape of a token and returns raw emails.
// So the report builds the expression maskplan would generate for that base
// column, has the server plan it, and requires the two plans to be
// identical (see canonicalPlan), key-table InitPlans included. Anything
// else, including correct masking written another way, is not recognized
// and is reported UNKNOWN.
func (s *pgState) recognize(v *viewPlan) (*recognized, error) {
	if !singleColumn(v.refs) {
		return nil, nil
	}
	_, pads, err := sqlexpr.KeySource(sqlexpr.Postgres, pgx.Identifier{s.internal, "key_material"}.Sanitize(), "k")
	if err != nil {
		return nil, err
	}
	type candidate struct{ transform, expr, join string }
	var cands []candidate
	base := v.refs[0]
	switch {
	case base.schema == s.internal && base.rel == "names" && base.col == "name":
		// fake_name and fake_email read the name dictionary, joined on the
		// base column's keyed index: the base column is in the join
		// condition, named by the join's alias.
		col, ok := strings.CutPrefix(base.alias, "fake_")
		if !ok {
			return nil, nil
		}
		var found []colRef
		for alias, rels := range v.rels {
			if len(rels) == 1 && rels[0].name != "" && rels[0].schema != s.internal {
				found = append(found, colRef{alias: alias, schema: rels[0].schema, rel: rels[0].name, col: col, resolved: true})
			}
		}
		if len(found) != 1 {
			return nil, nil
		}
		base = found[0]
		base.label, base.labeled = s.label(base.schema, base.rel, base.col)
		base.isPII = base.labeled && base.label.IsPII()
		for _, t := range []string{policy.FakeName, policy.FakeEmail} {
			expr, join, err := compile.ColumnSQL(sqlexpr.Postgres, policy.Decision{Transform: t, Label: base.label.Label}, compile.Column{Name: col}, base.alias, pads, s.internal)
			if err != nil {
				return nil, nil
			}
			cands = append(cands, candidate{t, expr, join})
		}
	case v.readsKey && tokenLabelRe.MatchString(v.output) && tokenLenRe.MatchString(v.output):
		lm := tokenLabelRe.FindStringSubmatch(v.output)
		nm := tokenLenRe.FindStringSubmatch(v.output)
		var n int
		if _, err := fmt.Sscanf(nm[1], "%d", &n); err != nil {
			return nil, nil
		}
		for _, norm := range []token.Normalizer{token.Email, token.Phone, token.Trim} {
			expr, err := sqlexpr.Token(sqlexpr.Postgres, sqlexpr.Column{
				Expr:        pgx.Identifier{base.alias, base.col}.Sanitize(),
				Label:       lm[1],
				Normalizer:  norm,
				TokenHexLen: 2 * n,
			}, pads)
			if err != nil {
				return nil, nil // not a label or length maskplan generates
			}
			cands = append(cands, candidate{policy.Token, expr, ""})
		}
	default:
		c := compile.Column{Name: base.col, Category: "D"}
		ds := []policy.Decision{{Transform: policy.GeneralizeYear}, {Transform: policy.GeneralizeMonth}}
		if m := prefixLenRe.FindStringSubmatch(v.output); m != nil {
			var n int
			if _, err := fmt.Sscanf(m[1], "%d", &n); err == nil {
				ds = append(ds, policy.Decision{Transform: policy.Prefix, Params: map[string]any{"keep": n}})
			}
		}
		for _, d := range ds {
			if expr, join, err := compile.ColumnSQL(sqlexpr.Postgres, d, c, base.alias, pads, s.internal); err == nil {
				cands = append(cands, candidate{d.Transform, expr, join})
			}
		}
	}
	from := pgx.Identifier{base.schema, base.rel}.Sanitize() + " " + pgx.Identifier{base.alias}.Sanitize()
	for _, c := range cands {
		q, err := s.reference(v, c.expr, from+c.join)
		if errors.Is(err, errNotReferenceable) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		if want, _, err := s.explainJSON(q); err == nil && want == v.canon {
			return &recognized{transform: c.transform, base: base}, nil
		}
	}
	return nil, nil
}

var errNotReferenceable = errors.New("no reference query for this shape")

// reference is the query whose plan the view column's plan must equal. It
// has the shape of a view so that the planner treats it like one: a
// subquery that is flattened, or for a view read through a Subquery Scan,
// the same subquery kept by OFFSET 0, with the view's own WHERE clause and
// the other outputs as the NULLs the planner made of them. (A query over
// one table also deparses its columns unqualified.) The view's WHERE
// clause is copied whatever it is: it decides which rows, not what a
// column's values are, and --policy checks it.
func (s *pgState) reference(v *viewPlan, expr, from string) (string, error) {
	sq := v.barrier
	if sq != nil && sq.nested {
		return "", errNotReferenceable
	}
	where, err := s.viewWhere(v.schema, v.view)
	if err != nil {
		return "", err
	}
	if where != "" {
		where = " WHERE " + where
	}
	if sq == nil {
		return fmt.Sprintf("SELECT v.c FROM (SELECT %s AS c FROM %s%s) v", expr, from, where), nil
	}
	cols := make([]string, len(sq.outputs))
	for i, o := range sq.outputs {
		if i == sq.pos {
			cols[i] = expr + " AS " + pgx.Identifier{sq.col}.Sanitize()
		} else {
			cols[i] = o + " AS " + pgx.Identifier{fmt.Sprintf("%s_%d", sq.col, i)}.Sanitize()
		}
	}
	return fmt.Sprintf("SELECT %s FROM (SELECT %s FROM %s%s OFFSET 0) %s",
		pgx.Identifier{sq.alias, sq.col}.Sanitize(), strings.Join(cols, ", "), from, where, pgx.Identifier{sq.alias}.Sanitize()), nil
}

// viewWhere returns the top-level WHERE clause of a view's definition, or
// "" if it has none. A clause it gets wrong only makes plans differ.
func (s *pgState) viewWhere(schema, view string) (string, error) {
	k := schema + "." + view
	if w, ok := s.wheres[k]; ok {
		return w, nil
	}
	var def string
	if err := s.tx.QueryRow(s.ctx, "SELECT pg_get_viewdef(to_regclass($1), false)", pgx.Identifier{schema, view}.Sanitize()).Scan(&def); err != nil {
		return "", err
	}
	w := topLevelWhere(def)
	s.wheres[k] = w
	return w, nil
}

func topLevelWhere(def string) string {
	depth, at := 0, -1
	isWord := func(b byte) bool {
		return b == '_' || b == '$' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
	}
	for i := 0; i < len(def); i++ {
		switch c := def[i]; c {
		case '\'', '"':
			for i++; i < len(def) && (def[i] != c || i+1 < len(def) && def[i+1] == c); i++ {
				if def[i] == c {
					i++ // a doubled quote
				}
			}
			if i >= len(def) {
				return ""
			}
		case '(':
			depth++
		case ')':
			depth--
		case 'W':
			if depth == 0 && strings.HasPrefix(def[i:], "WHERE") && (i == 0 || !isWord(def[i-1])) &&
				(i+5 == len(def) || !isWord(def[i+5])) {
				at = i + 5
			}
		}
	}
	if at < 0 {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(def[at:]), ";"))
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
		s.read[v.schema+"."+v.rel] = true
		obj := v.schema + "." + v.rel + "." + v.col
		access := "view: " + s.explain(v)
		p, err := s.lineage(v.schema, v.rel, v.col)
		var pgErr *pgconn.PgError
		if s.opts.AsRole && errors.As(err, &pgErr) && pgErr.Code == "42501" {
			// The role holds SELECT on the view but cannot read through it:
			// a security_invoker view over tables it has no rights on.
			s.add(Finding{Status: Warn, Object: obj, Path: "SELECT on the view, but planning it as " + s.report.Role + " is denied (" + pgErr.Message + "); " + access})
			continue
		}
		if err != nil {
			s.add(Finding{Status: Unknown, Object: obj, Path: fmt.Sprintf("cannot trace view column (EXPLAIN failed: %v); %s", err, access)})
			continue
		}
		if p.barrier != nil {
			s.filtered[v.schema+"."+v.rel] = true
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
		short := printableExpr(expr)
		passthrough := len(pii) == 1 && len(refs) == 1 && trimParens(expr) == pii[0].raw
		var rec *recognized
		if !passthrough {
			if rec, err = s.recognize(p); err != nil {
				return err
			}
		}
		switch {
		case passthrough && pii[0].label.DerivedFrom != "":
			s.add(Finding{Status: Unknown, Object: obj, Label: pii[0].label.Label, Path: "passes through " + derivedPath(pii[0].schema, pii[0].rel, pii[0].label) + "; " + access})
		case passthrough:
			base := pii[0].schema + "." + pii[0].rel + "." + pii[0].col
			s.add(Finding{Status: Raw, Object: obj, Label: pii[0].label.Label, Path: "passes through " + base + "; " + access})
		case rec != nil:
			r := rec.base
			s.add(Finding{Status: Masked, Object: obj, Label: r.label.Label, Path: "maskplan " + rec.transform + " of " + r.schema + "." + r.rel + "." + r.col})
		case len(pii) > 0:
			s.add(Finding{Status: Unknown, Object: obj, Label: pii[0].label.Label, Path: "expression over " + pii[0].schema + "." + pii[0].rel + "." + pii[0].col + " is not a maskplan transform: " + short + "; " + access})
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

// conditionFindings checks what a view's own conditions read. They run on
// base rows whatever the role selects, with the base columns' raw values,
// and can pass them to the role: a function that raises a notice, a cast
// that fails with the value in its error (WHERE email::int > 0). A
// condition that reads a personal-data column is UNKNOWN, unless --policy
// says the view is the policy's. Only conditions the plan shows on columns
// it can trace are checked.
func (s *pgState) conditionFindings() error {
	for _, k := range sortedKeys(s.read) {
		if s.matched[k] {
			continue
		}
		schema, view, _ := strings.Cut(k, ".")
		_, root, err := s.explainAs("SELECT 1 FROM "+pgx.Identifier{schema, view}.Sanitize(), true)
		var pgErr *pgconn.PgError
		if s.opts.AsRole && errors.As(err, &pgErr) && pgErr.Code == "42501" {
			continue // the role cannot read through it; its columns say so
		}
		if err != nil {
			s.add(Finding{Status: Unknown, Object: "view " + k, Path: fmt.Sprintf("cannot check the view's conditions (EXPLAIN failed: %v)", err)})
			continue
		}
		aliases := map[string][]rel{}
		var conds []string
		var walk func(n *planNode)
		walk = func(n *planNode) {
			if n.Alias != "" {
				aliases[n.Alias] = append(aliases[n.Alias], rel{n.Schema, n.RelationName})
			}
			conds = append(conds, n.conditions()...)
			for i := range n.Plans {
				walk(&n.Plans[i])
			}
		}
		walk(root)
	conditions:
		for _, c := range conds {
			for _, m := range refRe.FindAllStringSubmatch(literalRe.ReplaceAllString(c, "''"), -1) {
				base := aliases[unquote(m[1])]
				if len(base) != 1 || base[0].name == "" {
					continue
				}
				col := unquote(m[2])
				if l, ok := s.label(base[0].schema, base[0].name, col); ok && l.IsPII() {
					s.add(Finding{Status: Unknown, Object: "view " + k, Label: l.Label,
						Path: fmt.Sprintf("its condition %s reads %s.%s.%s raw for every row, whatever the role selects; errors and functions in it can pass the value on%s",
							printableExpr(c), base[0].schema, base[0].name, col, s.policyHint())})
					break conditions
				}
			}
		}
	}
	return nil
}

func (s *pgState) policyHint() string {
	if s.opts.Policy == nil {
		return " (if it is a maskplan rows filter, pass --policy)"
	}
	return ""
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
