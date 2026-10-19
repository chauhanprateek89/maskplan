package report

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
)

// PolicySource picks the policy source a report checks: name, or the
// policy's only source of engine when name is empty.
func PolicySource(p *policy.Policy, engine, name string) (string, error) {
	if name != "" {
		s, ok := p.Sources[name]
		if !ok {
			return "", fmt.Errorf("policy has no source %q", name)
		}
		if s.Engine != engine {
			return "", fmt.Errorf("policy source %s is %s, not %s", name, s.Engine, engine)
		}
		return name, nil
	}
	var found []string
	for n, s := range p.Sources {
		if s.Engine == engine {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		slices.Sort(found)
		return "", fmt.Errorf("policy has %d %s sources (%s); choose one with --source", len(found), engine, strings.Join(found, ", "))
	}
	return found[0], nil
}

// policyFindings compares the role's views with the ones the policy
// compiles to. Column findings already say whether each column is raw or
// masked; this says whether the views are the policy's, which covers what
// column findings cannot: which rows the role sees. A row filter dropped,
// changed or widened (OR true) gives a different plan.
//
// Without a policy, a row-filtered view gets a WARN: its filter is shown
// but not checked.
func (s *pgState) policyFindings() error {
	p := s.opts.Policy
	if p == nil {
		for _, k := range sortedKeys(s.filtered) {
			schema, view, _ := strings.Cut(k, ".")
			where, err := s.viewWhere(schema, view)
			if err != nil {
				return err
			}
			if where != "" {
				s.add(Finding{Status: Warn, Object: "view " + k, Path: "shows only rows where " + s.expr(where) + "; not checked against a policy (pass --policy)"})
			}
		}
		return nil
	}
	role := s.report.Role
	if _, ok := p.Identities[role]; !ok {
		s.add(Finding{Status: Warn, Object: "policy", Path: role + " is not an identity in the policy; its views were not compared with it"})
		return nil
	}
	tables, err := s.policyTables(p, role)
	if err != nil {
		return err
	}
	for _, t := range tables {
		v, sel, _, err := compile.ViewSelect(sqlexpr.Postgres, p, s.opts.Source, role, t, s.cls, s.internal)
		if err != nil {
			return err
		}
		obj := "view " + role + "." + t.Name
		if sel == "" {
			continue
		}
		var cols []string
		var barrier bool
		err = s.tx.QueryRow(s.ctx, `SELECT (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a
				WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped),
			EXISTS (SELECT FROM unnest(c.reloptions) o WHERE o ~* '^security_barrier=(true|on|yes|1)$')
			FROM pg_class c WHERE c.oid = to_regclass($1) AND c.relkind = 'v'`,
			pgx.Identifier{role, t.Name}.Sanitize()).Scan(&cols, &barrier)
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		if err != nil {
			return err
		}
		if cols == nil {
			s.add(Finding{Status: Warn, Object: obj, Path: "in the policy but missing; run maskplan apply"})
			continue
		}
		var want []string
		for _, c := range v.Columns {
			want = append(want, c.Name)
		}
		filter := ""
		if v.Filter != "" {
			filter = "; the policy's rows filter is " + s.expr(v.Filter)
		}
		if !slices.Equal(cols, want) {
			s.add(Finding{Status: Unknown, Object: obj, Path: fmt.Sprintf("has columns %s; the policy's view has %s; run maskplan apply",
				strings.Join(cols, ", "), strings.Join(want, ", "))})
			continue
		}
		if v.Filter != "" && !barrier {
			// Then the planner may run the role's own WHERE clause first,
			// on rows the filter excludes: SELECT * FROM view WHERE
			// leak(col) sees every row's masked values.
			s.add(Finding{Status: Unknown, Object: obj, Path: "is not a security_barrier view, so the role's own conditions can see rows outside its filter" + filter + "; run maskplan apply"})
			continue
		}
		// The plans cannot tell a barrier view from a plain one: the
		// planner removes a Subquery Scan that only passes its rows on.
		ref := sel
		if v.Filter != "" {
			ref += " OFFSET 0" // a security_barrier view is not flattened either
		}
		got, _, err := s.explainJSON("SELECT * FROM " + pgx.Identifier{role, t.Name}.Sanitize())
		if err != nil {
			s.add(Finding{Status: Unknown, Object: obj, Path: fmt.Sprintf("cannot compare with the policy (EXPLAIN failed: %v)", err)})
			continue
		}
		refPlan, _, err := s.explainJSON(fmt.Sprintf("SELECT * FROM (%s) %s", ref, pgx.Identifier{t.Name}.Sanitize()))
		if err != nil {
			s.add(Finding{Status: Unknown, Object: obj, Path: fmt.Sprintf("cannot compare with the policy (EXPLAIN of the policy's view failed: %v)", err)})
			continue
		}
		if got != refPlan {
			s.add(Finding{Status: Unknown, Object: obj, Path: "is not the view the policy compiles to (its columns, transforms or rows differ)" + filter + "; run maskplan apply"})
			continue
		}
		s.matched[role+"."+t.Name] = true
	}
	return nil
}

// policyTables reads the catalog entries of the identity's tables in the
// report's source.
func (s *pgState) policyTables(p *policy.Policy, identity string) ([]*compile.Table, error) {
	all := map[[2]string]*compile.Table{}
	rows, err := s.tx.Query(s.ctx, `SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), t.typcategory::text
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_type t ON t.oid = a.atttypid
		WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT c.relispartition
			AND n.nspname || '.' || c.relname = ANY ($1)
		ORDER BY 1, 2, a.attnum`, specNames(p.Identities[identity].Tables))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var schema, table string
		var c compile.Column
		if err := rows.Scan(&schema, &table, &c.Name, &c.Type, &c.Category); err != nil {
			rows.Close()
			return nil, err
		}
		k := [2]string{schema, table}
		if all[k] == nil {
			all[k] = &compile.Table{Schema: schema, Name: table}
		}
		all[k].Columns = append(all[k].Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return compile.IdentityTables(p, s.opts.Source, identity, all)
}

func specNames(specs []string) []string {
	out := make([]string, len(specs))
	for i, spec := range specs {
		if _, name, ok := strings.Cut(spec, ":"); ok {
			spec = name
		}
		out[i] = spec
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
