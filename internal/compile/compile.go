// Package compile turns a policy into the statements that build each
// identity's masked views, login and settings. It is a pure function of the
// policy, the classification, the source's catalog and what the source
// already has; package apply gathers those and runs the result.
package compile

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// Column and Table describe the source's catalog.
type Column struct {
	Name, Type string
	Category   string // pg_type.typcategory: D for dates and times
}

type Table struct {
	Schema, Name string
	Columns      []Column
}

// State is what the source has before apply: facts the plan depends on.
type State struct {
	Tables           map[[2]string]*Table
	Roles            map[string]bool // every role that exists
	Schemas          map[string]bool // every schema that exists
	Owned            map[[2]string]string
	HasPgaudit       bool
	HasRdsIam        bool
	AllTablesPublish []string // FOR ALL TABLES publications
}

// Object is something apply creates and records as its own.
type Object struct {
	Kind, Name, Identity string
}

// Statement is one step of a plan. Args carry the key and other secrets, so
// SQL never contains them and a printed plan never shows them.
type Statement struct {
	SQL     string
	Args    []any
	Comment string
	Display string // printed instead of SQL when SQL holds a secret
}

// ViewColumn is one column of a masked view.
type ViewColumn struct {
	Name     string
	Decision policy.Decision
}

// View is one masked view.
type View struct {
	Identity, Name string
	Base           [2]string
	Columns        []ViewColumn
	Filter         string
}

// Plan is what apply will do on one source.
type Plan struct {
	Source     string
	Statements []Statement
	Views      []View
	Owns       []Object
	Warnings   []string
}

// DefaultInternal is the schema of maskplan's own tables.
const DefaultInternal = "maskplan_internal"

func qi(parts ...string) string { return pgx.Identifier(parts).Sanitize() }

// NormalizerFor picks the token normalizer for a label.
func NormalizerFor(label string) token.Normalizer {
	switch label {
	case classify.Email:
		return token.Email
	case classify.Phone:
		return token.Phone
	}
	return token.Trim
}

// lowEntropy labels have few possible values: with a leaked key their
// tokens can be reversed by trying them all.
var lowEntropy = map[string]bool{classify.BirthDate: true, classify.PostalCode: true, classify.Gender: true, classify.Marital: true}

// IdentityTables returns the tables of an identity that live in source.
func IdentityTables(p *policy.Policy, source, identity string, all map[[2]string]*Table) ([]*Table, error) {
	id := p.Identities[identity]
	var out []*Table
	for _, spec := range id.Tables {
		src, name, qualified := strings.Cut(spec, ":")
		if !qualified {
			name, src = spec, ""
		}
		if src != "" && src != source {
			continue
		}
		schema, table, ok := strings.Cut(name, ".")
		if !ok {
			return nil, fmt.Errorf("identity %s: table %q, want schema.table", identity, spec)
		}
		t, ok := all[[2]string{schema, table}]
		if !ok {
			if src == source {
				return nil, fmt.Errorf("identity %s: table %s does not exist in source %s", identity, name, source)
			}
			continue // another source's table
		}
		out = append(out, t)
	}
	return out, nil
}

// Postgres compiles the policy for one Postgres source. key is the HMAC key.
// internal names maskplan's own schema; empty means DefaultInternal.
func Postgres(p *policy.Policy, source string, cls *classification.File, st *State, key []byte, passwords map[string]string, internal string) (*Plan, error) {
	if internal == "" {
		internal = DefaultInternal
	}
	if len(st.AllTablesPublish) > 0 {
		return nil, fmt.Errorf("publication %s replicates all tables, which would include the key table; give it an explicit table list first",
			strings.Join(st.AllTablesPublish, ", "))
	}
	plan := &Plan{Source: source}
	labels := cls.Index()
	add := func(comment, sql string, args ...any) {
		plan.Statements = append(plan.Statements, Statement{SQL: sql, Args: args, Comment: comment})
	}
	ipad, opad := token.Pads(key)
	add("maskplan's own schema: no role but the one running apply can use it",
		"CREATE SCHEMA IF NOT EXISTS "+qi(internal))
	add("", "REVOKE ALL ON SCHEMA "+qi(internal)+" FROM PUBLIC")
	add("the key, as HMAC pads; views read it with their owner's rights",
		"CREATE TABLE IF NOT EXISTS "+qi(internal, "key_material")+" (id smallint PRIMARY KEY CHECK (id = 1), ipad bytea NOT NULL, opad bytea NOT NULL)")
	add("written as parameters: the key never appears in SQL text, logs or this plan",
		"INSERT INTO "+qi(internal, "key_material")+" VALUES (1, $1, $2) ON CONFLICT (id) DO UPDATE SET ipad = EXCLUDED.ipad, opad = EXCLUDED.opad", ipad, opad)
	add("the fake-name dictionary", "CREATE TABLE IF NOT EXISTS "+qi(internal, "names")+" (i int PRIMARY KEY, name text NOT NULL)")
	add("", "INSERT INTO "+qi(internal, "names")+" SELECT i - 1, n FROM unnest($1::text[]) WITH ORDINALITY AS d(n, i) ON CONFLICT (i) DO UPDATE SET name = EXCLUDED.name", Names())
	add("what apply created, so it changes and drops nothing else",
		"CREATE TABLE IF NOT EXISTS "+qi(internal, "objects")+" (kind text NOT NULL, name text NOT NULL, identity text NOT NULL, PRIMARY KEY (kind, name))")

	_, pads, err := sqlexpr.KeySource(sqlexpr.Postgres, qi(internal, "key_material"), "")
	if err != nil {
		return nil, err
	}
	identities := make([]string, 0, len(p.Identities))
	for name, id := range p.Identities {
		for _, s := range id.Sources {
			if s == source {
				identities = append(identities, name)
			}
		}
	}
	sort.Strings(identities)
	wanted := map[[2]string]bool{}
	for _, name := range identities {
		id := p.Identities[name]
		tables, err := IdentityTables(p, source, name, st.Tables)
		if err != nil {
			return nil, err
		}
		owner, roleOwned := st.Owned[[2]string{"role", name}]
		if st.Roles[name] && (!roleOwned || owner != name) {
			return nil, fmt.Errorf("role %s already exists and maskplan did not create it; choose another identity name", name)
		}
		if st.Schemas[name] && st.Owned[[2]string{"schema", name}] != name {
			return nil, fmt.Errorf("schema %s already exists and maskplan did not create it; choose another identity name", name)
		}
		login := "NOLOGIN"
		if id.Login != "none" {
			login = "LOGIN"
		}
		if !st.Roles[name] {
			add("identity "+name, fmt.Sprintf("CREATE ROLE %s %s", qi(name), login))
		}
		add("", fmt.Sprintf("ALTER ROLE %s %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT", qi(name), login))
		plan.Owns = append(plan.Owns, Object{"role", name, name}, Object{"schema", name, name})
		wanted[[2]string{"role", name}], wanted[[2]string{"schema", name}] = true, true
		switch id.Login {
		case "iam":
			if !st.HasRdsIam {
				return nil, fmt.Errorf("identity %s: login iam needs the rds_iam role (RDS and Aurora); on Cloud SQL create an IAM user instead", name)
			}
			add("", fmt.Sprintf("GRANT rds_iam TO %s", qi(name)))
		case "password":
			verifier, err := scramVerifier(passwords[name])
			if err != nil {
				return nil, fmt.Errorf("identity %s: %w", name, err)
			}
			add("a SCRAM verifier, not the password", fmt.Sprintf("ALTER ROLE %s PASSWORD '%s'", qi(name), verifier))
			plan.Statements[len(plan.Statements)-1].Display = fmt.Sprintf("ALTER ROLE %s PASSWORD '…'", qi(name))
		}
		add("", fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", qi(name)))
		add("", fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM PUBLIC", qi(name)))
		add("", fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", qi(name), qi(name)))
		add("", fmt.Sprintf("ALTER ROLE %s SET search_path = %s", qi(name), qi(name)))
		if id.Limits.Connections > 0 {
			add("enforced by the server", fmt.Sprintf("ALTER ROLE %s CONNECTION LIMIT %d", qi(name), id.Limits.Connections))
		} else {
			add("", fmt.Sprintf("ALTER ROLE %s CONNECTION LIMIT -1", qi(name)))
		}
		if id.Audit == "read" {
			if !st.HasPgaudit {
				return nil, fmt.Errorf("identity %s: audit read needs pgaudit, which is not loaded on source %s", name, source)
			}
			add("audit every read by this identity", fmt.Sprintf("ALTER ROLE %s SET pgaudit.log = 'read'", qi(name)))
		}
		if id.Limits.StatementTimeout != "" {
			add("advisory: the session can override it", fmt.Sprintf("ALTER ROLE %s SET statement_timeout = %s", qi(name), quoteLiteral(id.Limits.StatementTimeout)))
		}

		for _, t := range tables {
			v, sel, warnings, err := ViewSelect(p, source, name, t, labels, pads, internal)
			if err != nil {
				return nil, err
			}
			plan.Warnings = append(plan.Warnings, warnings...)
			if sel == "" {
				continue
			}
			view := qi(name, t.Name)
			options := ""
			if v.Filter != "" {
				// A row filter must not leak through functions in the agent's
				// own WHERE clause: keep the view a barrier.
				options = " WITH (security_barrier)"
			}
			add("", "DROP VIEW IF EXISTS "+view)
			add(fmt.Sprintf("%s reads %s.%s", name, t.Schema, t.Name), fmt.Sprintf("CREATE VIEW %s%s AS\n%s", view, options, sel))
			add("", "REVOKE ALL ON "+view+" FROM PUBLIC")
			add("", fmt.Sprintf("GRANT SELECT ON %s TO %s", view, qi(name)))
			plan.Views = append(plan.Views, v)
			plan.Owns = append(plan.Owns, Object{"view", name + "." + t.Name, name})
			wanted[[2]string{"view", name + "." + t.Name}] = true
		}
	}
	// Drop what an earlier apply created and the policy no longer wants:
	// views first, then schemas, then roles.
	var stale []Object
	for k, identity := range st.Owned {
		if !wanted[k] {
			stale = append(stale, Object{k[0], k[1], identity})
		}
	}
	sortObjects(stale)
	for _, o := range stale {
		for i, q := range dropSQL(o, st) {
			comment := ""
			if i == 0 {
				comment = "no longer in the policy"
			}
			add(comment, q)
		}
		add("", "DELETE FROM "+qi(internal, "objects")+" WHERE kind = $1 AND name = $2", o.Kind, o.Name)
	}
	for _, o := range plan.Owns {
		add("", "INSERT INTO "+qi(internal, "objects")+" VALUES ($1, $2, $3) ON CONFLICT (kind, name) DO UPDATE SET identity = EXCLUDED.identity", o.Kind, o.Name, o.Identity)
	}
	return plan, nil
}

// ViewSelect returns identity's view of t and its SELECT, or an empty
// SELECT when every column is excluded. report --policy compares views
// with it.
func ViewSelect(p *policy.Policy, source, identity string, t *Table, labels map[classification.Key]classification.Column, pads sqlexpr.Pads, internal string) (v View, sel string, warnings []string, err error) {
	id := p.Identities[identity]
	v = View{Identity: identity, Name: t.Name, Base: [2]string{t.Schema, t.Name}, Filter: id.Rows[t.Schema+"."+t.Name]}
	if f, ok := id.Rows[source+":"+t.Schema+"."+t.Name]; ok {
		v.Filter = f
	}
	var exprs, joins []string
	for _, c := range t.Columns {
		lc, labeled := labels[classification.Key{Schema: t.Schema, Table: t.Name, Column: c.Name}]
		d := p.Decide(source, classification.Column{Schema: t.Schema, Table: t.Name, Column: c.Name, Label: lc.Label, DerivedFrom: lc.DerivedFrom}, labeled)
		expr, join, err := ColumnSQL(d, c, "b", pads, internal)
		if err != nil {
			return v, "", nil, fmt.Errorf("%s.%s.%s: %w", t.Schema, t.Name, c.Name, err)
		}
		if d.Transform == policy.Exclude {
			continue
		}
		if d.Transform == policy.Token && lowEntropy[d.Label] {
			warnings = append(warnings, fmt.Sprintf("%s.%s.%s (%s) is tokenized; it has few possible values, so anyone with the key can reverse its tokens by trying them all; consider generalize or prefix", t.Schema, t.Name, c.Name, d.Label))
		}
		if d.Transform == policy.Allow && d.Label != "" && d.Label != classification.None {
			warnings = append(warnings, fmt.Sprintf("%s.%s.%s (%s) is exposed raw to %s by %s", t.Schema, t.Name, c.Name, d.Label, identity, d.Why))
		}
		exprs = append(exprs, expr+" AS "+qi(c.Name))
		if join != "" {
			joins = append(joins, join)
		}
		v.Columns = append(v.Columns, ViewColumn{Name: c.Name, Decision: d})
	}
	if len(exprs) == 0 {
		warnings = append(warnings, fmt.Sprintf("%s.%s: every column is excluded for %s; no view", t.Schema, t.Name, identity))
		return v, "", warnings, nil
	}
	where := ""
	if v.Filter != "" {
		where = "\nWHERE " + v.Filter
	}
	sel = fmt.Sprintf("SELECT %s\nFROM %s b%s%s", strings.Join(exprs, ",\n       "), qi(t.Schema, t.Name), strings.Join(joins, ""), where)
	return v, sel, warnings, nil
}

// DestroyPostgres drops everything apply created on a source: the views,
// schemas and roles its objects table records, then its own schema with
// the key.
func DestroyPostgres(st *State, internal string) *Plan {
	if internal == "" {
		internal = DefaultInternal
	}
	plan := &Plan{}
	objs := make([]Object, 0, len(st.Owned))
	for k, identity := range st.Owned {
		objs = append(objs, Object{k[0], k[1], identity})
	}
	sortObjects(objs)
	for _, o := range objs {
		for _, q := range dropSQL(o, st) {
			plan.Statements = append(plan.Statements, Statement{SQL: q})
		}
	}
	plan.Statements = append(plan.Statements, Statement{SQL: "DROP SCHEMA IF EXISTS " + qi(internal) + " CASCADE", Comment: "maskplan's own schema and the key"})
	return plan
}

// sortObjects orders objects for dropping: views, then schemas, then roles.
func sortObjects(objs []Object) {
	order := map[string]int{"view": 0, "schema": 1, "role": 2}
	sort.Slice(objs, func(i, j int) bool {
		if order[objs[i].Kind] != order[objs[j].Kind] {
			return order[objs[i].Kind] < order[objs[j].Kind]
		}
		return objs[i].Name < objs[j].Name
	})
}

// dropSQL drops one object. A role first loses what it owns and was
// granted in this database (maskplan's roles own nothing of their own), so
// that a grant someone added by hand does not stop the drop.
func dropSQL(o Object, st *State) []string {
	switch o.Kind {
	case "view":
		schema, view, _ := strings.Cut(o.Name, ".")
		return []string{"DROP VIEW IF EXISTS " + qi(schema, view)}
	case "schema":
		return []string{"DROP SCHEMA IF EXISTS " + qi(o.Name) + " CASCADE"}
	}
	if !st.Roles[o.Name] {
		return nil
	}
	return []string{"DROP OWNED BY " + qi(o.Name), "DROP ROLE " + qi(o.Name)}
}

// ColumnSQL returns a view column's expression and, for fake transforms,
// the dictionary join it needs. The base table's alias is alias.
func ColumnSQL(d policy.Decision, c Column, alias string, pads sqlexpr.Pads, internal string) (expr, join string, err error) {
	ref := qi(alias, c.Name)
	col := sqlexpr.Column{Expr: ref, Label: d.Label, Normalizer: NormalizerFor(d.Label)}
	if col.Label == "" || col.Label == classification.None {
		col.Label = "maskplan.unlabeled"
	}
	switch d.Transform {
	case policy.Allow:
		return ref, "", nil
	case policy.Exclude:
		return "", "", nil
	case policy.Null:
		return "NULL::" + c.Type, "", nil
	case policy.Token:
		e, err := sqlexpr.Token(sqlexpr.Postgres, col, pads)
		return e, "", err
	case policy.GeneralizeYear, policy.GeneralizeMonth:
		if c.Category != "D" {
			return "", "", fmt.Errorf("%s needs a date or timestamp column, not %s", d.Transform, c.Type)
		}
		if d.Transform == policy.GeneralizeYear {
			e, err := sqlexpr.GeneralizeYear(sqlexpr.Postgres, ref)
			return e, "", err
		}
		e, err := sqlexpr.GeneralizeMonth(sqlexpr.Postgres, ref)
		return e, "", err
	case policy.Prefix:
		n, err := policy.KeepParam(d.Params)
		if err != nil {
			return "", "", err
		}
		e, err := sqlexpr.Prefix(sqlexpr.Postgres, ref, n)
		return e, "", err
	case policy.FakeName, policy.FakeEmail:
		idx, err := sqlexpr.FakeIndex(sqlexpr.Postgres, col, pads, DictionarySize)
		if err != nil {
			return "", "", err
		}
		n := "fake_" + c.Name
		join = fmt.Sprintf("\nLEFT JOIN %s %s ON %s = %s", qi(internal, "names"), qi(n), qi(n, "i"), idx)
		if d.Transform == policy.FakeName {
			return qi(n, "name"), join, nil
		}
		e, err := sqlexpr.FakeEmail(sqlexpr.Postgres, qi(n, "name"))
		return e, join, err
	}
	return "", "", fmt.Errorf("unknown transform %q", d.Transform)
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// scramVerifier returns the SCRAM-SHA-256 verifier Postgres stores for a
// password, so the password itself is never sent or logged.
func scramVerifier(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("empty password")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const iterations = 4096
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	server := mac(salted, "Server Key")
	b := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b(salt), b(stored[:]), b(server)), nil
}

// Print writes a plan for people: comments and SQL, never the arguments.
func (p *Plan) Print(w io.Writer) {
	fmt.Fprintf(w, "-- source %s\n", p.Source)
	for _, s := range p.Statements {
		if s.Comment != "" {
			fmt.Fprintf(w, "\n-- %s\n", s.Comment)
		}
		sql := s.SQL
		if s.Display != "" {
			sql = s.Display
		}
		if len(s.Args) > 0 {
			sql += fmt.Sprintf("  -- with %d parameters, not shown", len(s.Args))
		}
		fmt.Fprintln(w, sql+";")
	}
	for _, warning := range p.Warnings {
		fmt.Fprintf(w, "\n-- warning: %s\n", warning)
	}
}
