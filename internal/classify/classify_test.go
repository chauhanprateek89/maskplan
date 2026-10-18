package classify

import (
	"fmt"
	"testing"
)

func TestByName(t *testing.T) {
	cases := map[string]string{
		"email":                 Email,
		"customer_email":        Email,
		"EmailAddress":          Email,
		"phone_number":          Phone,
		"mobile":                Phone,
		"firstName":             Name,
		"last_name":             Name,
		"full-name":             Name,
		"postcode":              PostalCode,
		"dob":                   BirthDate,
		"date_of_birth":         BirthDate,
		"ssn":                   NationalID,
		"ppsn":                  NationalID,
		"iban":                  IBAN,
		"card_number":           CardNumber,
		"ip_address":            IPAddress,
		"password_hash":         Secret,
		"api_key":               Secret,
		"customer_no":           UniqueID,
		"account_id":            "", // surrogate keys are not labeled
		"customer_id":           "",
		"name":                  "", // only in a table of people, see TestClassify
		"nationalidnumber":      NationalID,
		"reviewername":          Name,
		"cardholder_name":       Name,
		"loginid":               UniqueID,
		"username":              UniqueID,
		"passwordsalt":          Secret,
		"gender":                Gender,
		"maritalstatus":         Marital,
		"filename":              "",
		"committer_name":        Name,
		"author_name":           Name,
		"encrypted_credentials": Secret,
		"signing_key":           Secret,
		"hostname":              "",
		"notes":                 FreeText,
		"id":                    "",
		"created_at":            "",
		"total":                 "",
		"emailed_at_count":      "",
		"username_length":       "",
	}
	for in, want := range cases {
		if got := ByName(in); got != want {
			t.Errorf("ByName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValueDetectors(t *testing.T) {
	yes := map[string][]string{
		"email": {"alice@example.com", "x.y+tag@sub.example.ie", "bob@ex-ample.co.uk"},
		"iban":  {"IE29AIBK93115212345678", "GB82WEST12345698765432", "DE89 3704 0044 0532 0130 00"},
		"card":  {"4111111111111111", "5500 0000 0000 0004", "340000000000009"},
		"ip":    {"10.0.0.1", "2001:db8::1", "10.0.0.1/32", "2001:db8::/48"},
		"phone": {"+353 (0)1 234-5678", "01 234 5678", "+1-555-0100"},
	}
	no := map[string][]string{
		"email": {"alice@", "@example.com", "not an email", "a@b"},
		"iban":  {"IE29AIBK93115212345679", "XX00", "1234567890"},
		"card":  {"4111111111111112", "1234", "41111111111111111111"},
		"ip":    {"10.0.0.256", "localhost", "10.0.0.1/33"},
		"phone": {"12", "hello", "2026-10-17", "17/10/2026", "1234567.89"},
	}
	fns := map[string]func(string) bool{"email": IsEmail, "iban": IsIBAN, "card": IsCardNumber, "ip": IsIPAddress, "phone": IsPhone}
	for k, f := range fns {
		for _, v := range yes[k] {
			if !f(v) {
				t.Errorf("%s detector rejected %q", k, v)
			}
		}
		for _, v := range no[k] {
			if f(v) {
				t.Errorf("%s detector accepted %q", k, v)
			}
		}
	}
}

func TestClassify(t *testing.T) {
	emails := make([]string, 50)
	for i := range emails {
		emails[i] = fmt.Sprintf("user%d@example.com", i)
	}
	cards := []string{"4111111111111111", "5500000000000004", "340000000000009", "6011000000000004"}
	cases := []struct {
		name string
		in   Input
		want string
		conf float64
	}{
		{"email by name and values", Input{Name: "email", IsText: true, Samples: emails}, Email, 0.95},
		{"email by values only", Input{Name: "contact", IsText: true, Samples: emails}, Email, 0.9},
		{"email by name, values disagree", Input{Name: "email", IsText: true, Samples: []string{"n/a", "unknown"}}, Email, 0.4},
		{"card numbers in a code column", Input{Name: "ref", IsText: true, Samples: cards}, CardNumber, 0.9},
		{"name rule, no samples", Input{Name: "last_name", IsText: true}, Name, 0.6},
		{"dob on a text column", Input{Name: "dob", DataType: "text", IsText: true, Samples: []string{"x"}}, None, 0.3},
		{"dob on a date column", Input{Name: "dob", DataType: "date", IsDate: true}, BirthDate, 0.6},
		{"json without personal data", Input{Name: "payload", DataType: "jsonb", IsText: true, IsDoc: true, Samples: []string{`{"a": 1}`}}, None, 0.4},
		{"json with a personal key", Input{Name: "payload", DataType: "jsonb", IsText: true, IsDoc: true, Samples: []string{`{"doc": {"full_name": "A B"}}`}}, FreeText, 0.6},
		{"json with an email value", Input{Name: "data", DataType: "jsonb", IsText: true, IsDoc: true, Samples: []string{`["x", {"to": "a@example.com"}]`}}, FreeText, 0.6},
		{"xml with a personal tag", Input{Name: "demographics", DataType: "xml", IsText: true, IsDoc: true, Samples: []string{`<Survey><BirthDate>1970-01-01</BirthDate></Survey>`}}, FreeText, 0.6},
		{"namespaced xml tags", Input{Name: "resume", DataType: "xml", IsText: true, IsDoc: true, Samples: []string{`<ns:Resume xmlns:ns="x"><ns:Name><ns:Name.First>A</ns:Name.First></ns:Name></ns:Resume>`}}, FreeText, 0.6},
		{"unsampled document", Input{Name: "payload", DataType: "jsonb", IsDoc: true}, FreeText, 0.3},
		{"unsampled configuration", Input{Name: "feature_settings", DataType: "jsonb", IsDoc: true}, None, 0.4},
		{"boolean named like an email", Input{Name: "email_confirmed", Category: "B"}, None, 0.5},
		{"timestamp named like an email", Input{Name: "email_sent_at", Category: "D"}, None, 0.5},
		{"key named like an email", Input{Name: "email_id", Category: "N"}, None, 0.5},
		{"phone stored as a number", Input{Name: "msisdn", Category: "N"}, Phone, 0.6},
		{"email setting, not an address", Input{Name: "email_restrictions", Category: "S"}, None, 0.5},
		{"machine address", Input{Name: "smtp_address", Category: "S"}, None, 0.5},
		{"system message", Input{Name: "error_message", Category: "S"}, None, 0.5},
		{"name of a role", Input{Name: "name", Table: "member_roles", Category: "S"}, None, 0.5},
		{"content of a message", Input{Name: "content", Table: "ai_conversation_messages", Category: "S"}, FreeText, 0.6},
		{"content of a page", Input{Name: "content", Table: "wiki_pages", Category: "S"}, None, 0.5},
		{"name of a contact", Input{Name: "name", Table: "customer_relations_contacts", Category: "S"}, Name, 0.6},
		{"bare name in a table of people", Input{Name: "name", Table: "customers", IsText: true}, Name, 0.6},
		{"bare name in a product table", Input{Name: "name", Table: "product", IsText: true}, None, 0.5},
		{"phone-shaped national IDs", Input{Name: "nationalidnumber", IsText: true, Samples: []string{"295847284", "245797967"}}, NationalID, 0.6},
		{"phone-shaped card numbers failing Luhn", Input{Name: "cardnumber", IsText: true, Samples: []string{"33332664695310", "55552127249722"}}, CardNumber, 0.4},
		{"phone values with a phone name", Input{Name: "mobile", IsText: true, Samples: []string{"+353 87 123 4567"}}, Phone, 0.95},
		{"nothing matches", Input{Name: "status", IsText: true, Samples: []string{"active", "closed"}}, None, 0.5},
		{"mostly empty samples ignored", Input{Name: "contact", IsText: true, Samples: append([]string{"", " "}, emails[:5]...)}, Email, 0.9},
	}
	for _, c := range cases {
		got := Classify(c.in)
		if got.Label != c.want || got.Confidence != c.conf {
			t.Errorf("%s: got %s %.2f (%v), want %s %.2f", c.name, got.Label, got.Confidence, got.Evidence, c.want, c.conf)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%s: no evidence", c.name)
		}
	}
}
