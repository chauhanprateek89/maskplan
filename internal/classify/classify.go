// Package classify assigns PII labels to columns from their names, types and
// a bounded sample of values. Labels follow the Fides data-category taxonomy
// where one fits. Detection is deliberately simple and explainable: every
// label carries the evidence that produced it, for a person to review.
package classify

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"regexp"
	"strings"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

// Labels assigned by the classifier.
const (
	Email      = "user.contact.email"
	Phone      = "user.contact.phone"
	Name       = "user.name"
	Address    = "user.contact.address"
	PostalCode = "user.contact.address.postal_code"
	BirthDate  = "user.demographic.date_of_birth"
	NationalID = "user.government_id"
	IBAN       = "user.financial.bank_account"
	CardNumber = "user.financial.credit_card"
	IPAddress  = "user.device.ip_address"
	UniqueID   = "user.unique_id"
	Secret     = "system.authentication"
	Gender     = "user.demographic.gender"
	Marital    = "user.demographic.marital_status"
	FreeText   = classification.FreeText
	None       = classification.None
)

// nameRule maps a column-name pattern to a label. Patterns match the whole
// normalized name (lowercase, separators removed).
type nameRule struct {
	label string
	re    *regexp.Regexp
}

// qualifier is an optional suffix that keeps a contact column a contact.
const qualifier = `(_(address|addr|primary|secondary|alt|alternate|other|work|home|personal|private|business|contact|\d+))?`

var nameRules = []nameRule{
	// A qualifier may follow (email_primary, phone_2), but not any word:
	// email_restrictions, email_message_id and phone_verified are not
	// contact details.
	{Email, regexp.MustCompile(`^(.*_)?(e_?mail|email_?address|mail)` + qualifier + `$`)},
	{Phone, regexp.MustCompile(`^(.*_)?(phone|telephone|mobile|msisdn|cell|fax)(_?(number|no|num))?` + qualifier + `$`)},
	{Name, regexp.MustCompile(`^(.*_)?(first_?name|last_?name|full_?name|surname|given_?name|family_?name|middle_?name|forename|display_?name|nick_?name|maiden_?name|name_(first|last|middle|given|family|full)|` +
		`(customer|contact|client|reviewer|card_?holder|account_?holder|holder|beneficiary|payee|payer|applicant|guarantor|recipient|sender|signatory|director|employee|person|patient|member|` +
		`author|committer|creator|assignee|reporter|requester|submitter|approver|signer)_?name)$`)},
	{IPAddress, regexp.MustCompile(`^(.*_)?(ip|ip_?addr(ess)?|client_?ip|remote_?addr)$`)},
	{PostalCode, regexp.MustCompile(`^(.*_)?(post_?code|postal_?code|zip|zip_?code|eircode)$`)},
	{Address, regexp.MustCompile(`^(.*_)?(address|addr|street|address_?line_?\d*|city|town)$`)},
	{BirthDate, regexp.MustCompile(`^(.*_)?(dob|date_?of_?birth|birth_?date|birthday|birth_?dt)$`)},
	{NationalID, regexp.MustCompile(`^(.*_)?(ssn|nin|ni_?number|pps_?n?o?|ppsn|national_?id(_?(no|number|num))?|tax_?id(_?(no|number))?|passport_?(no|number)?|driving_?licen[cs]e(_?(no|number))?)$`)},
	{IBAN, regexp.MustCompile(`^(.*_)?(iban|bank_?account(_?(no|number))?|account_?number|sort_?code|bic)$`)},
	{CardNumber, regexp.MustCompile(`^(.*_)?(pan|card_?(no|number|num)|credit_?card(_?number)?|cc_?(no|number|num))$`)},
	{Secret, regexp.MustCompile(`^(.*_)?(password|passwd|pwd|password_?(hash|salt)|salt|secret|credentials?|api_?key|token|access_?token|refresh_?token|(private|secret|signing|encryption)_?key|otp_?secret)$`)},
	{Gender, regexp.MustCompile(`^(.*_)?(gender|sex)$`)},
	{Marital, regexp.MustCompile(`^(.*_)?(marital|civil)_?status$`)},
	// Business identifiers people are known by. Surrogate keys (customer_id)
	// are not labeled: they identify a row, and the columns that identify
	// the person are labeled where they live.
	{UniqueID, regexp.MustCompile(`^(.*_)?(customer_?(no|number|ref)|account_?(no|ref)|member_?(no|number)|client_?(no|ref)|login(_?(id|name))?|user_?name)$`)},
	{FreeText, regexp.MustCompile(`^(.*_)?(notes?|comments?|remarks?|message|description|bio|free_?text|body)$`)},
}

// normalizeName lowercases a column name and converts camelCase and
// separators to underscores, so firstName, first-name and FIRST_NAME match.
func normalizeName(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			if i > 0 && !strings.HasSuffix(b.String(), "_") {
				prev := s[i-1]
				if prev >= 'a' && prev <= 'z' {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r + ('a' - 'A'))
		case r == '-' || r == ' ' || r == '.':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ByName returns the label suggested by a column name, or "".
func ByName(column string) string {
	n := normalizeName(column)
	for _, r := range nameRules {
		if r.re.MatchString(n) {
			return r.label
		}
	}
	return ""
}

// personTableRe matches the last word of a table name that holds people:
// users, customer_contacts, salesperson. A bare "name" column is a person's
// name only there; elsewhere it names a product, a department, a role or a
// token (member_roles, personal_access_tokens).
var personTableRe = regexp.MustCompile(`(person|persons|people|customers?|clients?|users?|members?|employees?|staff|contacts?|patients?|students?|applicants?|candidates?|holders?|beneficiar(y|ies)|payees?|guarantors?|directors?|shareholders?|borrowers?|investors?|tenants?|guests?|passengers?|subscribers?|signator(y|ies)|individuals?)$`)

func isPersonTable(table string) bool {
	n := normalizeName(table)
	return personTableRe.MatchString(n[strings.LastIndex(n, "_")+1:])
}

// Prefixes that make an address or a message something other than
// personal data: smtp_address, error_message.
var (
	notAddressRe = regexp.MustCompile(`^(smtp|server|host|mac|ip|web|url|remote|wallet|contract|memory|ldap|bind|listen|proxy|node|peer|socket|endpoint|gateway|network|broadcast|return|bounce)_`)
	notTextRe    = regexp.MustCompile(`^(error|exception|status|log|system|failure|warning|debug)_`)
	// configDocRe names documents that hold configuration, not people.
	configDocRe = regexp.MustCompile(`^(.*_)?(config|configuration|settings?|options|metrics|(min_|max_)?cursor|filters?|spec|schema|permissions|polic(y|ies)|labels|features|params|parameters|arguments|stats|statistics|manifest|definition|rules|mapping|layout|state|licenses|dependencies|variables|thresholds)$`)
)

// messageTableRe matches the last word of a table of things people write.
var messageTableRe = regexp.MustCompile(`(messages?|comments?|notes?|posts?|chats?|conversations?|replies|reviews?|tickets?|feedbacks?)$`)

// byNameInTable is ByName, plus two rules that need the table: bare "name"
// in a table of people, and the text of a message (content, text) in a
// table of things people write.
func byNameInTable(column, table string) (string, string) {
	if l := ByName(column); l != "" {
		return l, fmt.Sprintf("column name %q matches the %s rule", column, l)
	}
	n, t := normalizeName(column), normalizeName(table)
	last := t[strings.LastIndex(t, "_")+1:]
	switch {
	case n == "name" && isPersonTable(table):
		return Name, fmt.Sprintf("column %q in table %q, which holds people", column, table)
	case (n == "content" || n == "text") && messageTableRe.MatchString(last):
		return FreeText, fmt.Sprintf("column %q in table %q, which holds what people write", column, table)
	}
	return "", ""
}

// Value detectors. Each must be specific enough that most matches in a
// sample really are that kind of value.
var (
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	phoneRe = regexp.MustCompile(`^\+?[0-9 ()./-]{7,24}$`)
	ibanRe  = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)
	panRe   = regexp.MustCompile(`^[0-9]{13,19}$`)
	// Dates and decimal amounts have phone-like shapes; exclude them.
	notPhoneRe = regexp.MustCompile(`^(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|-?\d+\.\d+)$`)
)

// IsEmail reports whether v looks like an email address.
func IsEmail(v string) bool { return emailRe.MatchString(strings.TrimSpace(v)) }

// IsPhone reports whether v looks like a phone number: 7 to 15 digits with
// only phone punctuation around them, and not a plain card-length number.
func IsPhone(v string) bool {
	v = strings.TrimSpace(v)
	if !phoneRe.MatchString(v) || notPhoneRe.MatchString(v) {
		return false
	}
	d := digits(v)
	return len(d) >= 7 && len(d) <= 15
}

// IsIBAN reports whether v is a structurally valid IBAN (ISO 13616 mod 97).
func IsIBAN(v string) bool {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), " ", ""))
	if !ibanRe.MatchString(s) {
		return false
	}
	rearranged := s[4:] + s[:4]
	var num strings.Builder
	for _, r := range rearranged {
		if r >= 'A' && r <= 'Z' {
			fmt.Fprintf(&num, "%d", r-'A'+10)
		} else {
			num.WriteRune(r)
		}
	}
	n, ok := new(big.Int).SetString(num.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

// IsCardNumber reports whether v is 13 to 19 digits (spaces and dashes
// allowed) passing the Luhn check.
func IsCardNumber(v string) bool {
	s := strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(v))
	if !panRe.MatchString(s) {
		return false
	}
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// IsIPAddress reports whether v parses as an IPv4 or IPv6 address, with or
// without a prefix length (Postgres renders inet as text with one: 10.0.0.1/32).
func IsIPAddress(v string) bool {
	v = strings.TrimSpace(v)
	if _, err := netip.ParseAddr(v); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(v)
	return err == nil
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// valueDetectors are tried in order; the first that matches enough of the
// sample wins. Card numbers come before phones because a 16-digit number
// that passes Luhn is far more likely a card.
var valueDetectors = []struct {
	label string
	match func(string) bool
	desc  string
}{
	{Email, IsEmail, "email addresses"},
	{IBAN, IsIBAN, "valid IBANs (mod 97)"},
	{CardNumber, IsCardNumber, "card numbers passing the Luhn check"},
	{IPAddress, IsIPAddress, "IP addresses"},
	{Phone, IsPhone, "phone numbers"},
}

// MinValueShare is the share of non-empty sampled values a detector must
// match before it labels a column.
const MinValueShare = 0.8

// Input describes one column to classify.
type Input struct {
	Name     string
	Table    string // the table's name, for context
	DataType string // engine type name, for evidence and type hints
	IsText   bool   // values are character data and were sampled
	IsDate   bool   // date or timestamp type
	IsDoc    bool   // JSON or XML document
	// Category is PostgreSQL's type category (S string, N numeric, D date
	// and time, B boolean, ...); empty means unknown and skips type checks.
	Category string
	Samples  []string // non-NULL sampled values; never stored
}

// Result is a label with its confidence and the evidence for it.
type Result struct {
	Label      string
	Confidence float64
	Evidence   []string
}

// Classify combines the name rule and the value detectors.
//
//   - A value detector matching at least MinValueShare of non-empty samples
//     wins, with confidence 0.95 if the name agrees and 0.9 otherwise. The
//     phone detector is weak (many identifiers are 7 to 15 digits), so it
//     does not override a name rule for another label.
//   - Otherwise a name rule gives its label with confidence 0.6, except that
//     a date-of-birth name needs a date type, and value-checked labels (email,
//     IBAN, card, IP, phone) drop to 0.4 when samples exist but do not match.
//   - Otherwise a document column (JSON, XML) is labeled free_text with
//     confidence 0.3: documents can hold personal data under any key.
//   - Otherwise the column is labeled none.
func Classify(in Input) Result {
	byName, nameEvidence := byNameInTable(in.Name, in.Table)
	if why := nameRuleDoesNotApply(byName, in); why != "" {
		return Result{Label: None, Confidence: 0.5, Evidence: []string{nameEvidence + ", but " + why}}
	}
	var weak string
	var nonEmpty []string
	for _, s := range in.Samples {
		if strings.TrimSpace(s) != "" {
			nonEmpty = append(nonEmpty, s)
		}
	}
	if in.IsText && len(nonEmpty) > 0 {
		for _, d := range valueDetectors {
			n := 0
			for _, s := range nonEmpty {
				if d.match(s) {
					n++
				}
			}
			if share := float64(n) / float64(len(nonEmpty)); share >= MinValueShare {
				ev := []string{fmt.Sprintf("%d of %d sampled values are %s", n, len(nonEmpty), d.desc)}
				if d.label == Phone && byName != "" && byName != Phone {
					weak = fmt.Sprintf("%d of %d sampled values look like phone numbers, but the name says otherwise", n, len(nonEmpty))
					break
				}
				conf := 0.9
				if byName == d.label {
					conf = 0.95
					ev = append(ev, "column name agrees")
				}
				return Result{Label: d.label, Confidence: conf, Evidence: ev}
			}
		}
	}
	switch {
	case byName == "" && in.IsDoc:
		return classifyDocument(in, nonEmpty)
	case byName == "":
		return Result{Label: None, Confidence: 0.5, Evidence: []string{"no name rule or value detector matched"}}
	case byName == BirthDate && !in.IsDate:
		return Result{Label: None, Confidence: 0.3, Evidence: []string{"name suggests a date of birth but the type is " + in.DataType}}
	}
	ev := []string{nameEvidence}
	if weak != "" {
		ev = append(ev, weak)
	}
	conf := 0.6
	if valueChecked(byName) && in.IsText && len(nonEmpty) > 0 {
		conf = 0.4
		ev = append(ev, "sampled values did not confirm it")
	}
	return Result{Label: byName, Confidence: conf, Evidence: ev}
}

// nameRuleDoesNotApply says why a name rule's label cannot be right for this
// column, or returns "". Names match loosely, so the type and the shape of
// the name have the last word: email_confirmed is a boolean, email_id a key.
func nameRuleDoesNotApply(label string, in Input) string {
	if label == "" {
		return ""
	}
	n := normalizeName(in.Name)
	switch {
	case in.Category == "B":
		return "the column is boolean"
	case in.Category == "D" && label != BirthDate:
		return "the column holds dates or times"
	case in.Category == "N" && !numericOK[label]:
		return "the column is a number"
	case strings.HasSuffix(n, "_id") && !idOK[label]:
		return "the name ends in _id, a key"
	case label == Address && notAddressRe.MatchString(n):
		return "the prefix names a machine address"
	case label == FreeText && notTextRe.MatchString(n):
		return "the prefix names system-generated text"
	}
	return ""
}

var (
	// numericOK are labels whose values are often stored as numbers.
	numericOK = map[string]bool{CardNumber: true, Phone: true, NationalID: true, UniqueID: true}
	// idOK are labels whose names legitimately end in _id.
	idOK = map[string]bool{NationalID: true, UniqueID: true}
)

func valueChecked(label string) bool {
	switch label {
	case Email, IBAN, CardNumber, IPAddress, Phone:
		return true
	}
	return false
}

// classifyDocument labels a JSON or XML column. With sampled documents it
// looks inside them: keys and tag names are checked against the name rules
// (full_name, dob, BirthDate) and string values against the value
// detectors. Keys like description or notes are structure, not evidence. Without samples it cannot tell, so it assumes free text unless
// the column's name says it holds configuration.
func classifyDocument(in Input, samples []string) Result {
	if len(samples) == 0 {
		if configDocRe.MatchString(normalizeName(in.Name)) {
			return Result{Label: None, Confidence: 0.4, Evidence: []string{"not sampled; the name says the " + in.DataType + " documents hold configuration"}}
		}
		return Result{Label: FreeText, Confidence: 0.3, Evidence: []string{"not sampled; " + in.DataType + " documents can hold personal data under any key"}}
	}
	found := map[string]bool{}
	var hits []string
	note := func(h string) {
		if !found[h] && len(hits) < 5 {
			found[h] = true
			hits = append(hits, h)
		}
	}
	for _, s := range samples {
		if strings.Contains(in.DataType, "xml") {
			for _, m := range xmlTagRe.FindAllStringSubmatch(s, -1) {
				if l := ByName(m[1]); l != "" && l != FreeText {
					note(fmt.Sprintf("tag <%s> (%s)", m[1], l))
				}
			}
			continue
		}
		var doc any
		if json.Unmarshal([]byte(s), &doc) == nil {
			walkJSON(doc, func(key string, value any) {
				if l := ByName(key); key != "" && l != "" && l != FreeText {
					note(fmt.Sprintf("key %q (%s)", key, l))
				}
				if v, ok := value.(string); ok {
					for _, d := range valueDetectors {
						if d.match(v) {
							note("values that are " + d.desc)
							break
						}
					}
				}
			})
		}
	}
	if len(hits) > 0 {
		return Result{Label: FreeText, Confidence: 0.6, Evidence: []string{"sampled " + in.DataType + " documents contain " + strings.Join(hits, ", ")}}
	}
	return Result{Label: None, Confidence: 0.4, Evidence: []string{fmt.Sprintf("%d sampled %s documents contain no personal-data keys or values", len(samples), in.DataType)}}
}

// xmlTagRe captures element names, without a namespace prefix (ns:Name.First).
var xmlTagRe = regexp.MustCompile(`<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?([A-Za-z_][A-Za-z0-9_.-]*)`)

// walkJSON calls f for every object member (with its key) and array element
// (with an empty key), depth first.
func walkJSON(v any, f func(key string, value any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			f(k, e)
			walkJSON(e, f)
		}
	case []any:
		for _, e := range x {
			f("", e)
			walkJSON(e, f)
		}
	}
}
