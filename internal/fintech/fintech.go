// Package fintech loads testdata/fintech: a synthetic Irish retail bank
// whose every column has a known label (testdata/fintech/labels.yaml). It is
// the classifier's held-out accuracy test and a demo database.
//
// The data is generated from a seed, so a load is reproducible. Values have
// the shapes real systems hold: IBANs with valid check digits in printed and
// electronic form, Luhn-valid card numbers stored as numbers and as typed
// text, PPSNs with valid check letters, Irish phone numbers in several
// formats, junk values, and a column that is NULL in older rows. No value
// describes a real person.
package fintech

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand/v2"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Options configures a load.
type Options struct {
	Schema    string // default fintech; dropped and recreated
	Customers int    // default 10000; other tables scale with it
	Seed      uint64 // default 1
}

// Load creates the schema from schemaSQL (testdata/fintech/schema.sql) and
// fills it.
func Load(ctx context.Context, conn *pgx.Conn, schemaSQL string, o Options) error {
	if o.Schema == "" {
		o.Schema = "fintech"
	}
	if o.Customers == 0 {
		o.Customers = 10000
	}
	if o.Seed == 0 {
		o.Seed = 1
	}
	ddl, err := os.ReadFile(schemaSQL)
	if err != nil {
		return err
	}
	schema := pgx.Identifier{o.Schema}.Sanitize()
	for _, q := range []string{
		"DROP SCHEMA IF EXISTS " + schema + " CASCADE",
		"CREATE SCHEMA " + schema,
		"SET search_path TO " + schema,
		string(ddl),
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			return err
		}
	}
	defer conn.Exec(ctx, "RESET search_path")
	g := &gen{r: newRand(o.Seed)}
	tables := g.tables(o.Customers)
	for _, t := range tables {
		if _, err := conn.CopyFrom(ctx, pgx.Identifier{o.Schema, t.name}, t.cols, pgx.CopyFromRows(t.rows)); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
	}
	if _, err := conn.Exec(ctx, "REFRESH MATERIALIZED VIEW "+schema+".monthly_net"); err != nil {
		return err
	}
	// Only this schema: a bare ANALYZE would take the whole database.
	// Partitioned tables are analyzed with their partitions.
	for _, t := range append(tables, table{name: "monthly_net"}) {
		if _, err := conn.Exec(ctx, "ANALYZE "+pgx.Identifier{o.Schema, t.name}.Sanitize()); err != nil {
			return err
		}
	}
	return nil
}

func newRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, 0x6d61736b706c616e)) }

type table struct {
	name string
	cols []string
	rows [][]any
}

type gen struct{ r *rand.Rand }

func (g *gen) pick(xs ...string) string { return xs[g.r.IntN(len(xs))] }
func (g *gen) chance(p float64) bool    { return g.r.Float64() < p }
func (g *gen) digits(n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(byte('0' + g.r.IntN(10)))
	}
	return b.String()
}

var (
	firstNames = []string{"Aoife", "Ciara", "Siobhan", "Niamh", "Saoirse", "Emma", "Sophie", "Grace", "Mary", "Anna",
		"Sean", "Conor", "Cian", "Oisin", "Darragh", "Jack", "James", "Daniel", "Michael", "Patrick",
		"Fatima", "Wei", "Piotr", "Agnieszka", "Lucas", "Mateo", "Priya", "Arjun", "Olena", "Andrei"}
	lastNames = []string{"Murphy", "Kelly", "O'Sullivan", "Walsh", "Smith", "O'Brien", "Byrne", "Ryan", "O'Connor", "O'Neill",
		"O'Reilly", "Doyle", "McCarthy", "Gallagher", "Doherty", "Kennedy", "Lynch", "Murray", "Quinn", "Moore",
		"Nowak", "Kowalski", "Silva", "Santos", "Chen", "Wang", "Patel", "Sharma", "Kovalenko", "Popescu"}
	places = [][3]string{ // town, county, Eircode routing key
		{"Dublin 2", "Dublin", "D02"}, {"Dublin 8", "Dublin", "D08"}, {"Swords", "Dublin", "K67"}, {"Cork", "Cork", "T12"},
		{"Galway", "Galway", "H91"}, {"Limerick", "Limerick", "V94"}, {"Waterford", "Waterford", "X91"},
		{"Kilkenny", "Kilkenny", "R95"}, {"Sligo", "Sligo", "F91"}, {"Athlone", "Westmeath", "N37"},
		{"Drogheda", "Louth", "A92"}, {"Tralee", "Kerry", "V92"}, {"Letterkenny", "Donegal", "F92"}}
	streets  = []string{"Main Street", "Church Road", "Station Road", "Patrick Street", "Mill Lane", "The Green", "Castle Avenue", "Seaview Park"}
	domains  = []string{"gmail.com", "outlook.com", "yahoo.ie", "eircom.net", "icloud.com", "hotmail.com", "proton.me"}
	merchant = []string{"TESCO", "DUNNES STORES", "SUPERVALU", "LIDL", "CIRCLE K", "LEAP CARD", "SPOTIFY", "AMAZON EU", "IRISH RAIL", "ELECTRIC IRELAND"}
)

func (g *gen) first() string { return g.pick(firstNames...) }
func (g *gen) last() string  { return g.pick(lastNames...) }

// ibanCheck returns the two check digits for country and BBAN (ISO 13616).
func ibanCheck(country, bban string) string {
	var num strings.Builder
	for _, c := range bban + country + "00" {
		if c >= 'A' && c <= 'Z' {
			fmt.Fprintf(&num, "%d", c-'A'+10)
		} else {
			num.WriteRune(c)
		}
	}
	n, _ := new(big.Int).SetString(num.String(), 10)
	return fmt.Sprintf("%02d", 98-new(big.Int).Mod(n, big.NewInt(97)).Int64())
}

func (g *gen) iban(country string) string {
	var bban string
	switch country {
	case "IE":
		bban = g.pick("AIBK", "BOFI", "IPBS", "ULSB", "PTSB") + g.digits(6) + g.digits(8)
	case "GB":
		bban = g.pick("BARC", "HBUK", "LOYD", "NWBK", "MONZ") + g.digits(6) + g.digits(8)
	case "DE":
		bban = g.digits(18)
	case "FR":
		bban = g.digits(23)
	case "NL":
		bban = g.pick("ABNA", "INGB", "RABO", "BUNQ") + g.digits(10)
	}
	return country + ibanCheck(country, bban) + bban
}

// printed groups an IBAN in fours, as on statements.
func printed(iban string) string {
	var parts []string
	for i := 0; i < len(iban); i += 4 {
		parts = append(parts, iban[i:min(i+4, len(iban))])
	}
	return strings.Join(parts, " ")
}

func luhnDigit(body string) byte {
	sum := 0
	for i := len(body) - 1; i >= 0; i-- {
		d := int(body[i] - '0')
		if (len(body)-1-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return byte('0' + (10-sum%10)%10)
}

func (g *gen) pan() string {
	body := g.pick("4", "51", "52", "53", "54", "55")
	body += g.digits(15 - len(body))
	return body + string(luhnDigit(body))
}

// ppsn returns a Personal Public Service Number with a valid check letter;
// newer numbers carry a second letter.
func (g *gen) ppsn() string {
	d := g.digits(7)
	sum := 0
	for i := range 7 {
		sum += int(d[i]-'0') * (8 - i)
	}
	second := ""
	if g.chance(0.4) {
		second = "A"
		sum += 9 * 1
	}
	check := "W"
	if m := sum % 23; m > 0 {
		check = string(rune('A' + m - 1))
	}
	return d + check + second
}

func (g *gen) eircode(key string) string {
	const set = "ACDEFHKNPRTVWXY0123456789"
	b := []byte{"ACDEFHKNPRTVWXY"[g.r.IntN(15)]}
	for range 3 {
		b = append(b, set[g.r.IntN(len(set))])
	}
	return key + " " + string(b)
}

func (g *gen) mobile() string {
	n := g.pick("83", "85", "86", "87", "89") + g.digits(7)
	switch g.r.IntN(4) {
	case 0:
		return "+353 " + n[:2] + " " + n[2:5] + " " + n[5:]
	case 1:
		return "0" + n[:2] + " " + n[2:5] + " " + n[5:]
	case 2:
		return "0" + n
	}
	return "+353" + n
}

func (g *gen) landline() string {
	switch g.r.IntN(3) {
	case 0:
		return "01 " + g.digits(3) + " " + g.digits(4)
	case 1:
		return "(021) " + g.digits(3) + " " + g.digits(4)
	}
	return "+353 1 " + g.digits(3) + " " + g.digits(4)
}

func (g *gen) email(first, last string) string {
	local := strings.ToLower(strings.ReplaceAll(first+"."+last, "'", ""))
	if g.chance(0.3) {
		local += g.digits(2)
	}
	e := local + "@" + g.pick(domains...)
	if g.chance(0.2) {
		e = strings.ToUpper(e[:1]) + e[1:]
	}
	return e
}

func (g *gen) ip() netip.Addr {
	if g.chance(0.2) {
		return netip.MustParseAddr(fmt.Sprintf("2a02:8084:%x:%x::%x", g.r.IntN(65536), g.r.IntN(65536), g.r.IntN(65536)))
	}
	return netip.AddrFrom4([4]byte{byte(80 + g.r.IntN(120)), byte(g.r.IntN(256)), byte(g.r.IntN(256)), byte(1 + g.r.IntN(254))})
}

var base = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func (g *gen) day() time.Time { return base.AddDate(0, 0, g.r.IntN(365)) }
func (g *gen) instant() time.Time {
	return base.Add(time.Duration(g.r.Int64N(int64(365 * 24 * time.Hour))))
}

// nullable returns v, or NULL when ok is false.
func nullable(ok bool, v any) any {
	if !ok {
		return nil
	}
	return v
}

// junk returns v, or now and then NULL or a placeholder people type.
func (g *gen) junk(v string) any {
	switch {
	case g.chance(0.08):
		return nil
	case g.chance(0.04):
		return g.pick("n/a", "", "unknown", "-", "none")
	}
	return v
}

type person struct{ first, last string }

func (g *gen) tables(n int) []table {
	people := make([]person, n)
	customers := table{name: "customers", cols: []string{"id", "customer_ref", "first_name", "last_name", "date_of_birth", "ppsn", "email", "mobile", "home_phone",
		"address_line_1", "address_line_2", "town", "county", "eircode", "gender", "nationality", "occupation", "annual_income", "risk_score",
		"kyc_status", "kyc_payload", "marketing_opt_in", "created_at"}}
	for i := range n {
		p := person{g.first(), g.last()}
		people[i] = p
		place := places[g.r.IntN(len(places))]
		dob := time.Date(1940+g.r.IntN(65), time.Month(1+g.r.IntN(12)), 1+g.r.IntN(28), 0, 0, 0, 0, time.UTC)
		kyc, _ := json.Marshal(map[string]any{
			"document": g.pick("passport", "driving_licence", "national_id_card"),
			"number":   "P" + g.digits(7), "full_name": p.first + " " + p.last,
			"dob": dob.Format("2006-01-02"), "verified": g.chance(0.9), "provider": g.pick("onfido", "veriff", "manual"),
		})
		customers.rows = append(customers.rows, []any{
			int64(i + 1), fmt.Sprintf("CUS-%07d", 1000+i), p.first, p.last, dob, g.ppsn(),
			g.junk(g.email(p.first, p.last)),
			nullable(i >= n*3/10 && !g.chance(0.05), g.mobile()), // column added after 30% of customers
			nullable(g.chance(0.4), g.landline()),
			fmt.Sprintf("%d %s", 1+g.r.IntN(200), g.pick(streets...)), nullable(g.chance(0.3), "Apartment "+g.digits(2)),
			place[0], place[1], g.eircode(place[2]), g.pick("female", "male", "female", "male", "non-binary", "undisclosed"),
			g.pick("Irish", "Irish", "Irish", "Polish", "British", "Brazilian", "Indian", "Ukrainian"),
			g.pick("Nurse", "Teacher", "Software engineer", "Student", "Retired", "Electrician", "Accountant", "Chef"),
			float64(15000+g.r.IntN(150000)) + 0.5, int32(g.r.IntN(1000)), g.pick("verified", "verified", "pending", "rejected"),
			string(kyc), g.chance(0.4), g.instant(),
		})
	}

	accounts := table{name: "accounts", cols: []string{"id", "customer_id", "iban", "bic", "sort_code", "account_number", "currency", "balance_cents", "opened_on", "status"}}
	cards := table{name: "cards", cols: []string{"id", "account_id", "pan", "pan_last4", "cardholder_name", "expiry_month", "expiry_year", "network", "status"}}
	var owner []int
	for i := range n * 6 / 5 {
		c := i % n
		owner = append(owner, c)
		iban := g.iban("IE")
		accounts.rows = append(accounts.rows, []any{int64(i + 1), int64(c + 1), printed(iban), iban[4:8] + "IE2D", iban[8:10] + "-" + iban[10:12] + "-" + iban[12:14],
			iban[14:], "EUR", int64(g.r.IntN(5_000_000)) - 200_000, g.day(), g.pick("open", "open", "open", "closed")})
		if i < n {
			pan := g.pan()
			var num int64
			fmt.Sscan(pan, &num)
			cards.rows = append(cards.rows, []any{int64(i + 1), int64(i + 1), num, pan[12:], strings.ToUpper(people[c].first + " " + people[c].last),
				int16(1 + g.r.IntN(12)), int16(2026 + g.r.IntN(5)), map[byte]string{'4': "visa", '5': "mastercard"}[pan[0]], g.pick("active", "active", "blocked")})
		}
	}

	payees := table{name: "payees", cols: []string{"id", "customer_id", "payee_name", "payee_iban", "reference", "created_at"}}
	for i := range 2 * n {
		name := g.first() + " " + g.last()
		if g.chance(0.2) {
			name = g.pick("Electric Ireland", "Bord Gais Energy", "Dublin City Council", "Revenue Commissioners", "Vodafone Ireland")
		}
		payees.rows = append(payees.rows, []any{int64(i + 1), int64(g.r.IntN(n) + 1), name, g.iban(g.pick("IE", "IE", "IE", "GB", "DE")),
			g.pick("Rent", "Rent for "+g.pick(streets...), "Birthday "+g.first(), "INV-"+g.digits(5), "Loan repayment", "Savings"), g.instant()})
	}

	tx := table{name: "transactions", cols: []string{"id", "account_id", "booked_at", "amount_cents", "currency", "counterparty_name", "counterparty_iban",
		"description", "merchant_category", "terminal_id", "device_ip", "channel"}}
	for i := range 10 * n {
		card := g.chance(0.6)
		row := []any{int64(i + 1), int64(g.r.IntN(len(owner)) + 1), g.day(), -int64(100 + g.r.IntN(50_000)), "EUR", nil, nil, nil, nil, nil, nil, nil}
		if card {
			m := g.pick(merchant...)
			row[5], row[7], row[8], row[9], row[11] = m, "CARD PAYMENT "+m, int32(5000+g.r.IntN(1000)), g.digits(8), g.pick("pos", "contactless", "online")
		} else {
			name := g.first() + " " + g.last()
			row[5], row[6] = name, g.iban(g.pick("IE", "IE", "GB", "DE", "FR", "NL"))
			row[7] = g.pick("Transfer to "+name, "SEPA CT "+strings.ToUpper(name), "Rent", "Split dinner "+g.first(), "Standing order")
			row[10], row[11] = g.ip(), g.pick("app", "web")
			if g.chance(0.3) {
				row[3] = -row[3].(int64) // incoming
			}
		}
		tx.rows = append(tx.rows, row)
	}

	tickets := table{name: "support_tickets", cols: []string{"id", "customer_id", "contact_value", "callback", "subject", "body", "created_at"}}
	for i := range n / 2 {
		c := g.r.IntN(n)
		p := people[c]
		tickets.rows = append(tickets.rows, []any{int64(i + 1), int64(c + 1), g.junk(g.email(p.first, p.last)), nullable(g.chance(0.7), g.mobile()),
			g.pick("Card lost", "Payment not received", "Change of address", "Dispute a transaction", "Locked out of the app"),
			fmt.Sprintf("Hi, this is %s %s. %s Please call me back.", p.first, p.last,
				g.pick("My card was stolen in Cork.", "I moved to "+g.pick(streets...)+".", "A payment to "+g.first()+" did not arrive.")), g.instant()})
	}

	logins := table{name: "login_events", cols: []string{"id", "customer_id", "source_addr", "user_agent", "occurred_at", "success"}}
	for i := range 3 * n {
		logins.rows = append(logins.rows, []any{int64(i + 1), int64(g.r.IntN(n) + 1), g.ip().String(),
			g.pick("BankApp/5.2 (iPhone; iOS 18.1)", "BankApp/5.2 (Android 15; Pixel 8)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), g.instant(), !g.chance(0.05)})
	}

	staff := table{name: "staff", cols: []string{"id", "staff_no", "display_name", "work_email", "extension", "msisdn"}}
	for i := range 200 {
		p := person{g.first(), g.last()}
		var msisdn int64
		fmt.Sscan("353"+g.pick("83", "85", "86", "87", "89")+g.digits(7), &msisdn)
		staff.rows = append(staff.rows, []any{int32(i + 1), fmt.Sprintf("E%05d", 10000+i), p.first + " " + p.last,
			strings.ToLower(strings.ReplaceAll(p.first+"."+p.last, "'", "")) + "@bank.example.ie", g.digits(4), msisdn})
	}

	disputes := table{name: "card_disputes", cols: []string{"id", "card", "opened_at", "amount_cents", "reason", "notes"}}
	for i := range max(50, n/20) {
		pan := g.pan()
		disputes.rows = append(disputes.rows, []any{int64(i + 1), pan[:4] + " " + pan[4:8] + " " + pan[8:12] + " " + pan[12:], g.instant(), int64(g.r.IntN(100_000)),
			g.pick("fraud", "not received", "duplicate"), nullable(g.chance(0.6), "Customer "+g.first()+" says "+g.pick("card was cloned", "never ordered this", "charged twice"))})
	}

	legacy := table{name: "legacy_import", cols: []string{"row_no", "col_a", "col_b", "col_c", "col_d", "imported_at"}}
	for i := range max(100, n/10) {
		pan := g.pan()
		ref := g.digits(15)
		ref += string('0' + (luhnDigit(ref)-'0'+1)%10) // never a valid card number
		legacy.rows = append(legacy.rows, []any{int32(i + 1), g.iban(g.pick("IE", "GB")), pan[:4] + "-" + pan[4:8] + "-" + pan[8:12] + "-" + pan[12:],
			ref, fmt.Sprintf("%d.%02d", g.r.IntN(10000), g.r.IntN(100)), g.instant()})
	}

	products := table{name: "products", cols: []string{"id", "name", "ean", "fee_cents", "description"}}
	for i := range 300 {
		products.rows = append(products.rows, []any{int32(i + 1), g.pick("Current account", "Saver", "Credit card", "Mortgage", "Car loan") + " " + g.digits(2),
			"539" + g.digits(10), int64(g.r.IntN(5000)), "Standard " + g.pick("fees", "terms", "rates") + " apply"})
	}

	fx := table{name: "fx_rates", cols: []string{"rate_date", "from_currency", "to_currency", "rate", "batch_no"}}
	for d := range 365 {
		for _, c := range []string{"GBP", "USD", "PLN"} {
			var batch int64
			fmt.Sscan("1"+g.digits(9), &batch)
			fx.rows = append(fx.rows, []any{base.AddDate(0, 0, d), "EUR", c, 0.5 + g.r.Float64()*4, batch})
		}
	}
	return []table{customers, accounts, cards, payees, tx, tickets, logins, staff, disputes, legacy, products, fx}
}
