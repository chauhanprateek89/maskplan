package compile

import (
	"strings"
	"testing"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/policy"
)

func TestSameTableNameInTwoSchemas(t *testing.T) {
	p := &policy.Policy{
		Version: policy.Version, Key: "env:K",
		Sources:    map[string]policy.Source{"app": {Engine: "postgres", DSN: "env:D"}},
		Identities: map[string]policy.Identity{"agent": {Sources: []string{"app"}, Tables: []string{"public.orders", "archive.orders"}}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	st := &State{Tables: map[[2]string]*Table{}, Roles: map[string]bool{}, Schemas: map[string]bool{}, Owned: map[[2]string]string{}}
	for _, s := range []string{"public", "archive"} {
		st.Tables[[2]string{s, "orders"}] = &Table{Schema: s, Name: "orders", Columns: []Column{{Name: "id", Type: "integer"}}}
	}
	cls := &classification.File{Version: classification.Version}
	key := []byte("compile-test-key")
	for engine, compile := range map[string]func() (*Plan, error){
		"postgres": func() (*Plan, error) { return Postgres(p, "app", cls, st, key, nil, "") },
		"mysql":    func() (*Plan, error) { return MySQL(p, "app", cls, st, key, nil, "") },
	} {
		if _, err := compile(); err == nil || !strings.Contains(err.Error(), "would both be the view agent.orders") {
			t.Errorf("%s: err = %v", engine, err)
		}
	}
}
