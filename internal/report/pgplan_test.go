package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func canon(t *testing.T, plan string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(plan), &v); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(canonicalPlan(v))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func initPlanNode(name, alias string) string {
	return `{"Node Type": "Seq Scan", "Parent Relationship": "InitPlan", "Subplan Name": "` + name + `",
		"Relation Name": "key_material", "Schema": "i", "Alias": "` + alias + `", "Output": ["` + alias + `.ipad"]}`
}

func TestCanonicalPlan(t *testing.T) {
	// The view's plan: InitPlans 1 and 2 belonged to a removed join.
	view := `{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b",
		"Output": ["f($2, b.email, '$0 key_material_2.x')"], "Plans": [` +
		initPlanNode("InitPlan 1 (returns $0)", "key_material") + `, ` +
		initPlanNode("InitPlan 2 (returns $1)", "key_material_1") + `, ` +
		initPlanNode("InitPlan 3 (returns $2)", "key_material_2") + `]}`
	// The reference query: the same column, numbered from the start.
	ref := `{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b_1",
		"Output": ["f($0, b_1.email, '$0 key_material_2.x')"], "Plans": [` +
		initPlanNode("InitPlan 1 (returns $0)", "key_material") + `]}`
	if a, b := canon(t, view), canon(t, ref); a != b {
		t.Errorf("same column, different canonical plans:\n%s\n%s", a, b)
	}
	// PostgreSQL 17 names InitPlan outputs instead of numbering parameters.
	view17 := `{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b",
		"Output": ["f((InitPlan 2).col1, b.email)"], "Plans": [` +
		initPlanNode("InitPlan 1", "key_material") + `, ` + initPlanNode("InitPlan 2", "key_material_1") + `]}`
	ref17 := `{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b",
		"Output": ["f((InitPlan 1).col1, b.email)"], "Plans": [` + initPlanNode("InitPlan 1", "key_material") + `]}`
	if a, b := canon(t, view17), canon(t, ref17); a != b {
		t.Errorf("PostgreSQL 17: different canonical plans:\n%s\n%s", a, b)
	}
	// Different plans stay different: another column, another parameter.
	for _, other := range []string{
		`{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b", "Output": ["f($0, b.phone, '$0 key_material_2.x')"], "Plans": [` + initPlanNode("InitPlan 1 (returns $0)", "key_material") + `]}`,
		`{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b", "Output": ["f($0, b.email, '$0 key_material.x')"], "Plans": [` + initPlanNode("InitPlan 1 (returns $0)", "key_material") + `]}`,
		`{"Node Type": "Seq Scan", "Relation Name": "users", "Schema": "s", "Alias": "b", "Output": ["f($0, b.email, '$0 key_material_2.x')"]}`,
	} {
		if canon(t, other) == canon(t, ref) {
			t.Errorf("different plans became equal:\n%s", other)
		}
	}
	// A parameter no InitPlan returns: left as it is.
	foreign := `{"Node Type": "Result", "Output": ["$5"], "Plans": [` + initPlanNode("InitPlan 1 (returns $0)", "key_material") + `]}`
	if got := canon(t, foreign); !json.Valid([]byte(got)) || !strings.Contains(got, `"InitPlan 1 (returns $0)"`) {
		t.Errorf("foreign parameter: %s", got)
	}
}

func TestTopLevelWhere(t *testing.T) {
	for def, want := range map[string]string{
		" SELECT id\n   FROM t b\n  WHERE (tenant_id = 1);":                        "(tenant_id = 1)",
		" SELECT id FROM t b WHERE (b.x = 'WHERE (1)') ;":                          "(b.x = 'WHERE (1)')",
		" SELECT (SELECT 1 FROM u WHERE u.a = b.a) AS a FROM t b;":                 "",
		` SELECT "WHERE" FROM t b WHERE ("WHERE" = 'it''s');`:                      `("WHERE" = 'it''s')`,
		" SELECT id FROM t b WHERE (b.a IN (SELECT a FROM u WHERE u.ok)) AND b.c;": "(b.a IN (SELECT a FROM u WHERE u.ok)) AND b.c",
		" SELECT nowhere FROM t;":                                                  "",
		" SELECT 'unterminated FROM t WHERE x;":                                    "",
	} {
		if got := topLevelWhere(def); got != want {
			t.Errorf("topLevelWhere(%q) = %q, want %q", def, got, want)
		}
	}
}
