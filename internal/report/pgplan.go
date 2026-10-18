package report

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Plan canonicalization. Two queries that compute the same column can still
// get different EXPLAIN output for reasons that do not change the column:
//
//   - InitPlans nothing references. When a query reads one column of a
//     view, the planner removes the other columns and the joins only they
//     needed, but keeps the InitPlans those joins' conditions created. They
//     are never executed: an InitPlan runs when its parameter is first used.
//   - Numbering. InitPlans and their parameters are numbered in the order
//     the planner creates them, and relation aliases (key_material_4) in the
//     order of the query's range table, which includes removed columns.
//
// canonicalPlan drops unreferenced InitPlans, renumbers the rest in plan
// order, and renames relation aliases to rel#k, a form no SQL identifier
// prints as. Each rewrite maps distinct names to distinct names and leaves
// string literals alone, so plans that differ still differ afterwards.

var (
	initPlanNameRe = regexp.MustCompile(`^InitPlan (\d+)(?: \(returns ((?:\$\d+)(?:,\$\d+)*)\))?$`)
	// A string literal, a parameter, an InitPlan reference (PostgreSQL 17
	// prints (InitPlan 1).col1), or a qualified name's first part.
	planTokenRe = regexp.MustCompile(`'(?:[^']|'')*'|\$(\d+)|InitPlan (\d+)|("(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)\.`)
)

type initPlan struct {
	id     string
	params []string
	node   map[string]any
	used   bool
}

// canonicalPlan returns a canonical copy of an EXPLAIN (FORMAT JSON) plan
// tree. If the plan has parameters that no InitPlan returns, it returns the
// plan unchanged: renumbering would then be ambiguous.
func canonicalPlan(plan any) any {
	root, ok := plan.(map[string]any)
	if !ok {
		return plan
	}
	var inits []*initPlan
	byID, byParam := map[string]*initPlan{}, map[string]*initPlan{}
	var collect func(n map[string]any)
	collect = func(n map[string]any) {
		if n["Parent Relationship"] == "InitPlan" {
			name, _ := n["Subplan Name"].(string)
			if m := initPlanNameRe.FindStringSubmatch(name); m != nil {
				ip := &initPlan{id: m[1], node: n}
				if m[2] != "" {
					for _, p := range strings.Split(m[2], ",") {
						ip.params = append(ip.params, p[1:])
						byParam[p[1:]] = ip
					}
				}
				inits = append(inits, ip)
				byID[ip.id] = ip
			}
		}
		for _, c := range children(n) {
			collect(c)
		}
	}
	collect(root)

	// Mark what is referenced, starting from everything outside InitPlans.
	foreign := false
	var queue []*initPlan
	mark := func(s string) {
		for _, m := range planTokenRe.FindAllStringSubmatch(s, -1) {
			var ip *initPlan
			switch {
			case m[1] != "":
				if ip = byParam[m[1]]; ip == nil {
					foreign = true
				}
			case m[2] != "":
				if ip = byID[m[2]]; ip == nil {
					foreign = true
				}
			}
			if ip != nil && !ip.used {
				ip.used = true
				queue = append(queue, ip)
			}
		}
	}
	var scan func(n map[string]any)
	scan = func(n map[string]any) {
		for k, v := range n {
			if k != "Plans" && k != "Subplan Name" {
				eachString(v, mark)
			}
		}
		for _, c := range children(n) {
			if c["Parent Relationship"] == "InitPlan" && byID[initID(c)] != nil {
				continue // scanned once referenced
			}
			scan(c)
		}
	}
	scan(root)
	for len(queue) > 0 {
		ip := queue[0]
		queue = queue[1:]
		scan(ip.node)
	}
	if foreign {
		return plan
	}

	// Renumber the InitPlans that stay, and their parameters, in plan order.
	ids, params := map[string]string{}, map[string]string{}
	for _, ip := range inits {
		if ip.used {
			ids[ip.id] = strconv.Itoa(len(ids) + 1)
			for _, p := range ip.params {
				params[p] = strconv.Itoa(len(params))
			}
		}
	}
	// Relation aliases, in plan order, after unused InitPlans are gone.
	aliases := map[string]string{}
	perRel := map[string]int{}
	var prune func(n map[string]any) map[string]any
	prune = func(n map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range n {
			if k != "Plans" {
				out[k] = v
			}
		}
		if alias, ok := n["Alias"].(string); ok {
			if rel, ok := n["Relation Name"].(string); ok {
				if _, seen := aliases[alias]; !seen {
					perRel[rel]++
					aliases[alias] = fmt.Sprintf("%s#%d", rel, perRel[rel])
				}
			}
		}
		var kept []any
		for _, c := range children(n) {
			if c["Parent Relationship"] == "InitPlan" {
				if ip := byID[initID(c)]; ip != nil && !ip.used {
					continue
				}
			}
			kept = append(kept, prune(c))
		}
		if kept != nil {
			out["Plans"] = kept
		}
		return out
	}
	pruned := prune(root)
	rewrite := func(s string) string {
		return planTokenRe.ReplaceAllStringFunc(s, func(tok string) string {
			m := planTokenRe.FindStringSubmatch(tok)
			switch {
			case m[1] != "":
				return "$" + params[m[1]]
			case m[2] != "":
				return "InitPlan " + ids[m[2]]
			case m[3] != "":
				if a, ok := aliases[unquote(m[3])]; ok {
					return a + "."
				}
			}
			return tok
		})
	}
	var apply func(v any) any
	apply = func(v any) any {
		switch x := v.(type) {
		case string:
			return rewrite(x)
		case []any:
			out := make([]any, len(x))
			for i, e := range x {
				out[i] = apply(e)
			}
			return out
		case map[string]any:
			out := map[string]any{}
			for k, e := range x {
				if k == "Alias" {
					if s, ok := e.(string); ok {
						if a, ok := aliases[s]; ok {
							out[k] = a
							continue
						}
					}
				}
				out[k] = apply(e)
			}
			return out
		}
		return v
	}
	return apply(pruned)
}

func children(n map[string]any) []map[string]any {
	plans, _ := n["Plans"].([]any)
	out := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		if m, ok := p.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func initID(n map[string]any) string {
	name, _ := n["Subplan Name"].(string)
	if m := initPlanNameRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

func eachString(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, e := range x {
			eachString(e, f)
		}
	case map[string]any:
		for _, e := range x {
			eachString(e, f)
		}
	}
}
