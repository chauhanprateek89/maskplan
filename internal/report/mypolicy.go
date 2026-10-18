package report

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
)

// policyFindings compares the account's views with the ones the policy
// compiles to. MySQL views have no rows filter (apply refuses them), so the
// comparison is per column: the view's columns by name and order, and each
// column's transform and base column as recognized from its definition. A
// view with a WHERE clause is not the policy's.
func (s *myState) policyFindings() error {
	p := s.opts.Policy
	if p == nil {
		return nil
	}
	identity := s.self.user
	if _, ok := p.Identities[identity]; !ok {
		s.add(Finding{Status: Warn, Object: "policy", Path: s.self.String() + " is not an identity in the policy; its views were not compared with it"})
		return nil
	}
	tables, err := s.policyTables(p, identity)
	if err != nil {
		return err
	}
	for _, t := range tables {
		v, sel, _, err := compile.ViewSelect(sqlexpr.MySQL, p, s.opts.Source, identity, t, s.cls, s.internal)
		if err != nil {
			return err
		}
		if sel == "" {
			continue
		}
		obj := "view " + identity + "." + t.Name
		exprs, from, err := s.viewDefinition(identity, t.Name)
		if err != nil {
			s.add(Finding{Status: Warn, Object: obj, Path: "in the policy but missing; run maskplan apply"})
			continue
		}
		if why := s.policyDiff(identity, t, v, exprs, from); why != "" {
			s.add(Finding{Status: Unknown, Object: obj, Path: "is not the view the policy compiles to: " + why + "; run maskplan apply"})
			continue
		}
		s.matched[identity+"."+t.Name] = true
	}
	return nil
}

// policyDiff says how a view differs from the policy's, or "".
func (s *myState) policyDiff(identity string, t *compile.Table, v compile.View, exprs map[string]string, from map[string][2]string) string {
	if exprs == nil {
		return "its definition is not a single SELECT"
	}
	rest := strings.ToLower(s.viewFrom(identity, t.Name))
	for _, kw := range []string{" where ", " group by ", " having ", " limit ", " union ", " window "} {
		if len(splitTopLevel(rest, kw)) > 1 {
			return "it has a" + strings.TrimRight(kw, " ") + " clause"
		}
	}
	var cols, want []string
	if err := s.columnList(identity, t.Name, &cols); err != nil {
		return "its columns cannot be read"
	}
	for _, c := range v.Columns {
		want = append(want, c.Name)
	}
	if !slices.Equal(cols, want) {
		return fmt.Sprintf("it has columns %s; the policy's view has %s", strings.Join(cols, ", "), strings.Join(want, ", "))
	}
	base := ""
	for alias, rel := range from {
		if rel == [2]string{t.Schema, t.Name} {
			base = alias
		}
	}
	for _, c := range v.Columns {
		expr := exprs[c.Name]
		rec := s.recognized[identity+"."+t.Name+"."+c.Name]
		d := c.Decision
		ok := false
		switch d.Transform {
		case policy.Allow:
			ok = base != "" && expr == quoteMy(base)+"."+quoteMy(c.Name)
		case policy.Null:
			ok = expr == "NULL"
		case policy.Prefix:
			keep, _ := policy.KeepParam(d.Params)
			ok = rec != nil && rec.transform == d.Transform && rec.base == [2]string{t.Schema, t.Name} && rec.col == c.Name &&
				reflect.DeepEqual(rec.params, map[string]any{"keep": keep})
		default:
			ok = rec != nil && rec.transform == d.Transform && rec.base == [2]string{t.Schema, t.Name} && rec.col == c.Name
		}
		if !ok {
			return fmt.Sprintf("column %s is %s; the policy's is %s (%s)", c.Name, printableExpr(expr), d.Transform, d.Why)
		}
	}
	return ""
}

func (s *myState) columnList(db, table string, out *[]string) error {
	rows, err := s.tx.QueryContext(s.ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION", db, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return err
		}
		*out = append(*out, c)
	}
	return rows.Err()
}

// policyTables reads the catalog entries of the identity's tables.
func (s *myState) policyTables(p *policy.Policy, identity string) ([]*compile.Table, error) {
	all := map[[2]string]*compile.Table{}
	for _, name := range specNames(p.Identities[identity].Tables) {
		schema, table, ok := strings.Cut(name, ".")
		if !ok {
			continue
		}
		rows, err := s.tx.QueryContext(s.ctx, `SELECT COLUMN_NAME, COLUMN_TYPE, DATA_TYPE FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`, schema, table)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c compile.Column
			var dataType string
			if err := rows.Scan(&c.Name, &c.Type, &dataType); err != nil {
				rows.Close()
				return nil, err
			}
			switch dataType {
			case "date", "datetime", "timestamp":
				c.Category = "D"
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
	}
	return compile.IdentityTables(p, s.opts.Source, identity, all)
}

// conditionFindings: a view's WHERE clause runs on base rows whatever the
// account selects, with raw values, and a condition can hand them on in an
// error (JSON_EXTRACT on a value that is not JSON fails with it). A WHERE
// clause that reads a labeled column is UNKNOWN. Join conditions are not
// checked on MySQL yet.
func (s *myState) conditionFindings() error {
	for _, k := range sortedKeys(s.read) {
		if s.matched[k] {
			continue
		}
		db, view, _ := strings.Cut(k, ".")
		_, from, err := s.viewDefinition(db, view)
		if err != nil || from == nil {
			continue
		}
		parts := splitTopLevel(s.viewFrom(db, view), " where ")
		if len(parts) < 2 {
			continue
		}
		where := parts[len(parts)-1]
		for _, m := range my2PartRe.FindAllStringSubmatch(myLiteralRe.ReplaceAllString(where, "''"), -1) {
			rel, ok := from[unquoteMy(m[1])]
			if !ok {
				continue
			}
			col := unquoteMy(m[2])
			if l, ok := s.cls[classification.Key{Schema: rel[0], Table: rel[1], Column: col}]; ok && l.IsPII() {
				s.add(Finding{Status: Unknown, Object: "view " + k, Label: l.Label,
					Path: fmt.Sprintf("its condition %s reads %s.%s.%s raw for every row, whatever the account selects; errors in it can pass the value on",
						printableExpr(where), rel[0], rel[1], col)})
				break
			}
		}
	}
	return nil
}
