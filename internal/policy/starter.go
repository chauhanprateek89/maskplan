package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

// starterRule is the suggested transform for a label, and why.
type starterRule struct {
	transform, params, why string
}

// starterRules are conservative: what an agent usually needs to join,
// group and count stays usable; what it rarely needs is left out.
var starterRules = map[string]starterRule{
	"user.contact.email":               {Token, "", "same value, same token: agents can still join and count by customer"},
	"user.contact.phone":               {Token, "", ""},
	"user.device.ip_address":           {Token, "", ""},
	"user.unique_id":                   {Token, "", "usernames and logins"},
	"user.name":                        {FakeName, "", "readable, consistent per person, never a join key"},
	"user.demographic.date_of_birth":   {GeneralizeYear, "", "a token of a birth date can be reversed by trying every date"},
	"user.contact.address.postal_code": {Prefix, "{ keep: 3 }", "the routing key of an Irish Eircode or a UK outward code; adjust for your countries"},
	"user.contact.address":             {Exclude, "", "street addresses are rarely needed"},
	"user.government_id":               {Exclude, "", ""},
	"user.financial.bank_account":      {Exclude, "", ""},
	"user.financial.credit_card":       {Exclude, "", ""},
	"system.authentication":            {Exclude, "", "password hashes, API keys, secrets"},
	"user.demographic.gender":          {Exclude, "", "few values: tokens would be reversible"},
	"user.demographic.marital_status":  {Exclude, "", "few values: tokens would be reversible"},
}

// Starter writes a commented starter policy for one identity reading every
// table in cls. It is a draft for review: every line is meant to be read
// and changed.
func Starter(cls *classification.File, identity, clsPath string) (string, error) {
	if !identifierRe.MatchString(identity) {
		return "", fmt.Errorf("identity %q: want a lowercase identifier", identity)
	}
	engine := cls.Source.Engine
	if engine == "" {
		engine = "postgres"
	}
	tables := map[string]bool{}
	labels := map[string]int{}
	for _, c := range cls.Columns {
		tables[c.Schema+"."+c.Table] = true
		if c.IsPII() {
			labels[c.Label]++
		}
	}
	if len(tables) == 0 {
		return "", fmt.Errorf("the classification lists no tables: run maskplan scan first")
	}
	names := make([]string, 0, len(tables))
	for t := range tables {
		names = append(names, t)
	}
	sort.Strings(names)
	env := strings.ToUpper(identity) + "_PASSWORD"

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("# maskplan policy: a starter generated from %s. Review every line.\n", clsPath)
	w("# Then: maskplan plan (prints the SQL), maskplan apply --yes.\n")
	w("version: 1\n")
	w("key: env:MASKPLAN_KEY   # the HMAC key; keep it in a secret store, never in this file\n\n")
	w("sources:\n  app:\n    engine: %s\n", engine)
	w("    dsn: env:MASKPLAN_DSN   # an admin connection: apply creates roles and views\n")
	w("    classification: %s\n\n", clsPath)
	w("identities:\n  %s:\n    sources: [app]\n", identity)
	w("    tables:   # every table in the classification; remove what the agent does not need\n")
	for _, t := range names {
		w("      - %s\n", t)
	}
	w("    login: password   # or iam (RDS), or none\n")
	w("    password: env:%s\n", env)
	if engine == "postgres" {
		w("    audit: none       # read logs every read through pgaudit, if it is loaded\n")
	}
	w("    limits:\n      connections: 5\n")
	if engine == "postgres" {
		w("      statement_timeout: 30s   # advisory: a session can change it\n")
	}
	w("\ndefaults:\n")
	w("  unlabeled: exclude   # columns the classification does not list\n")
	w("  free_text: null      # notes, comments, messages: personal data hides in them\n")
	w("\n# One rule per label found. A personal-data label with no rule is excluded.\nrules:\n")
	found := make([]string, 0, len(labels))
	for l := range labels {
		found = append(found, l)
	}
	sort.Strings(found)
	for _, l := range found {
		if l == classification.FreeText {
			w("  # %s (%s): decided by defaults.free_text above\n", l, plural(labels[l], "column"))
			continue
		}
		r, ok := starterRules[l]
		if !ok {
			w("  # %s (%s): no suggestion; excluded until you add a rule\n", l, plural(labels[l], "column"))
			continue
		}
		params := ""
		if r.params != "" {
			params = ", params: " + r.params
		}
		comment := plural(labels[l], "column")
		if r.why != "" {
			comment += "; " + r.why
		}
		w("  - { label: %s, transform: %s%s }   # %s\n", l, r.transform, params, comment)
	}
	w("\n# overrides:\n#   - { column: app.schema.table.column, transform: exclude }\n")
	return b.String(), nil
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
