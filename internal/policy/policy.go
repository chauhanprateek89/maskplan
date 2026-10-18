// Package policy reads maskplan.yaml: which identities (agent logins) get
// which tables, and how each label is transformed for them. Rules attach to
// labels, not columns, so labeling a new column applies the right transform
// everywhere; anything the policy does not allow is left out.
package policy

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

// Version is the file format version.
const Version = 1

// Transforms.
const (
	Token           = "token"
	FakeName        = "fake_name"
	FakeEmail       = "fake_email"
	GeneralizeYear  = "generalize_year"
	GeneralizeMonth = "generalize_month"
	Prefix          = "prefix"
	Null            = "null"
	Exclude         = "exclude"
	Allow           = "allow"
)

var transforms = map[string]bool{Token: true, FakeName: true, FakeEmail: true, GeneralizeYear: true, GeneralizeMonth: true,
	Prefix: true, Null: true, Exclude: true, Allow: true}

// Policy is the layout of maskplan.yaml.
type Policy struct {
	Version    int                 `yaml:"version"`
	Key        string              `yaml:"key"` // env:NAME; the key is never stored in the file
	Sources    map[string]Source   `yaml:"sources"`
	Identities map[string]Identity `yaml:"identities"`
	Defaults   Defaults            `yaml:"defaults"`
	Rules      []Rule              `yaml:"rules"`
	Overrides  []Override          `yaml:"overrides"`
}

// Source is a database apply connects to as an administrator.
type Source struct {
	Engine         string `yaml:"engine"`         // postgres | mysql
	DSN            string `yaml:"dsn"`            // env:NAME, or a DSN without a password
	Classification string `yaml:"classification"` // path; default classification.yaml
}

// Identity is one agent login.
type Identity struct {
	Sources  []string          `yaml:"sources"`
	Tables   []string          `yaml:"tables"` // schema.table, or source:schema.table
	Login    string            `yaml:"login"`  // iam | password | none
	Password string            `yaml:"password"`
	Audit    string            `yaml:"audit"` // read | none
	Limits   Limits            `yaml:"limits"`
	Rows     map[string]string `yaml:"rows"` // table -> SQL predicate, per engine
}

// Limits are settings the database enforces, and one it does not.
type Limits struct {
	Connections      int    `yaml:"connections"`
	StatementTimeout string `yaml:"statement_timeout"` // advisory: the session can override it
}

// Defaults decide columns no rule covers.
type Defaults struct {
	Unlabeled string `yaml:"unlabeled"` // exclude | allow
	FreeText  string `yaml:"free_text"` // null | exclude | allow
}

// Rule is the transform for every column with a label.
type Rule struct {
	Label     string         `yaml:"label"`
	Transform string         `yaml:"transform"`
	Params    map[string]any `yaml:"params"`
}

// Override is the transform for one column: source.schema.table.column.
type Override struct {
	Column    string         `yaml:"column"`
	Transform string         `yaml:"transform"`
	Params    map[string]any `yaml:"params"`
}

// transformField returns a mapping's transform value as written: YAML reads
// transform: null as a null, not as the string null.
func transformField(n *yaml.Node) string {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k, v := n.Content[i], n.Content[i+1]; k.Value == "transform" && v.Kind == yaml.ScalarNode {
			if v.Tag == "!!null" && v.Value != "" {
				return Null
			}
			return v.Value
		}
	}
	return ""
}

// knownKeys does for these mappings what KnownFields does for the rest:
// node.Decode does not inherit it.
func knownKeys(n *yaml.Node, keys ...string) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		found := false
		for _, want := range keys {
			found = found || k.Value == want
		}
		if !found {
			return fmt.Errorf("line %d: field %s not found", k.Line, k.Value)
		}
	}
	return nil
}

func (r *Rule) UnmarshalYAML(n *yaml.Node) error {
	type plain Rule
	if err := knownKeys(n, "label", "transform", "params"); err != nil {
		return err
	}
	if err := n.Decode((*plain)(r)); err != nil {
		return err
	}
	r.Transform = transformField(n)
	return nil
}

func (o *Override) UnmarshalYAML(n *yaml.Node) error {
	type plain Override
	if err := knownKeys(n, "column", "transform", "params"); err != nil {
		return err
	}
	if err := n.Decode((*plain)(o)); err != nil {
		return err
	}
	o.Transform = transformField(n)
	return nil
}

var identifierRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a misspelled key is an error, not a silent default
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Validate checks the policy and fills in defaults.
func (p *Policy) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("unsupported version %d, want %d", p.Version, Version)
	}
	if !strings.HasPrefix(p.Key, "env:") || len(p.Key) <= 4 {
		return fmt.Errorf("key must be env:VARIABLE; the key is never written in the file")
	}
	if len(p.Sources) == 0 {
		return fmt.Errorf("no sources")
	}
	for name, s := range p.Sources {
		if s.Engine != "postgres" && s.Engine != "mysql" {
			return fmt.Errorf("source %s: engine %q, want postgres or mysql", name, s.Engine)
		}
		if s.Classification == "" {
			s.Classification = "classification.yaml"
			p.Sources[name] = s
		}
	}
	switch p.Defaults.Unlabeled {
	case "":
		p.Defaults.Unlabeled = Exclude
	case Exclude, Allow:
	default:
		return fmt.Errorf("defaults.unlabeled %q, want exclude or allow", p.Defaults.Unlabeled)
	}
	switch p.Defaults.FreeText {
	case "":
		p.Defaults.FreeText = Null
	case Null, Exclude, Allow:
	default:
		return fmt.Errorf("defaults.free_text %q, want null, exclude or allow", p.Defaults.FreeText)
	}
	if len(p.Identities) == 0 {
		return fmt.Errorf("no identities")
	}
	for name, id := range p.Identities {
		if !identifierRe.MatchString(name) {
			return fmt.Errorf("identity %q: want a lowercase identifier", name)
		}
		if len(id.Sources) == 0 {
			return fmt.Errorf("identity %s: no sources", name)
		}
		for _, s := range id.Sources {
			if _, ok := p.Sources[s]; !ok {
				return fmt.Errorf("identity %s: unknown source %q", name, s)
			}
		}
		switch id.Login {
		case "":
			id.Login = "none"
		case "iam", "none":
		case "password":
			if !strings.HasPrefix(id.Password, "env:") {
				return fmt.Errorf("identity %s: login password needs password: env:VARIABLE", name)
			}
		default:
			return fmt.Errorf("identity %s: login %q, want iam, password or none", name, id.Login)
		}
		switch id.Audit {
		case "":
			id.Audit = "none"
		case "read", "none":
		default:
			return fmt.Errorf("identity %s: audit %q, want read or none", name, id.Audit)
		}
		if len(id.Tables) == 0 {
			return fmt.Errorf("identity %s: no tables", name)
		}
		for t := range id.Rows {
			found := false
			for _, x := range id.Tables {
				found = found || x == t
			}
			if !found {
				return fmt.Errorf("identity %s: rows filter for %s, which is not in its tables", name, t)
			}
		}
		p.Identities[name] = id
	}
	labels := map[string]bool{}
	for i, r := range p.Rules {
		if r.Label == "" {
			return fmt.Errorf("rule %d: no label", i+1)
		}
		if labels[r.Label] {
			return fmt.Errorf("label %s has two rules", r.Label)
		}
		labels[r.Label] = true
		if err := checkTransform(r.Transform, r.Params); err != nil {
			return fmt.Errorf("rule for %s: %w", r.Label, err)
		}
	}
	for _, o := range p.Overrides {
		if strings.Count(o.Column, ".") != 3 {
			return fmt.Errorf("override %q: want source.schema.table.column", o.Column)
		}
		if err := checkTransform(o.Transform, o.Params); err != nil {
			return fmt.Errorf("override %s: %w", o.Column, err)
		}
	}
	return nil
}

func checkTransform(t string, params map[string]any) error {
	if !transforms[t] {
		names := make([]string, 0, len(transforms))
		for n := range transforms {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown transform %q, want one of %s", t, strings.Join(names, ", "))
	}
	if t == Prefix {
		if _, err := KeepParam(params); err != nil {
			return err
		}
	}
	return nil
}

// MaxKeep is the longest prefix: enough for a postcode's routing key or an
// IBAN's country and bank, short of most of an email or a name.
const MaxKeep = 8

// KeepParam returns prefix's keep parameter.
func KeepParam(params map[string]any) (int, error) {
	v, ok := params["keep"].(int)
	if !ok || v < 1 || v > MaxKeep {
		return 0, fmt.Errorf("prefix needs params: { keep: N } with N from 1 to %d", MaxKeep)
	}
	return v, nil
}

// Decision is what a column becomes in an identity's view, and why.
type Decision struct {
	Transform string
	Params    map[string]any
	Label     string
	Why       string
}

// Decide returns the transform for one column. The order: an override for
// the column; the rule for its label; allow for columns labeled none; the
// free-text default; the unlabeled default for columns the classification
// does not list. A personal-data label with no rule is excluded: the policy
// fails closed.
func (p *Policy) Decide(source string, c classification.Column, labeled bool) Decision {
	full := source + "." + c.Schema + "." + c.Table + "." + c.Column
	for _, o := range p.Overrides {
		if o.Column == full {
			return Decision{Transform: o.Transform, Params: o.Params, Label: c.Label, Why: "override"}
		}
	}
	switch {
	case !labeled:
		return Decision{Transform: p.Defaults.Unlabeled, Why: "not in the classification: defaults.unlabeled"}
	case c.DerivedFrom != "":
		return Decision{Transform: Exclude, Label: c.Label, Why: "a token column (derived_from " + c.DerivedFrom + "): not yet supported, excluded"}
	}
	for _, r := range p.Rules {
		if r.Label == c.Label {
			return Decision{Transform: r.Transform, Params: r.Params, Label: c.Label, Why: "rule for " + c.Label}
		}
	}
	switch c.Label {
	case classification.None:
		return Decision{Transform: Allow, Label: c.Label, Why: "labeled none"}
	case classification.FreeText:
		return Decision{Transform: p.Defaults.FreeText, Label: c.Label, Why: "defaults.free_text"}
	}
	return Decision{Transform: Exclude, Label: c.Label, Why: "no rule for " + c.Label + ": excluded"}
}

// Env resolves an env:NAME reference.
func Env(ref string) (string, error) {
	name, ok := strings.CutPrefix(ref, "env:")
	if !ok {
		return ref, nil
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	return v, nil
}
