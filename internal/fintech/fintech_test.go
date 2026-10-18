package fintech

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/accuracy"
	"github.com/chauhanprateek89/maskplan/internal/classify"
	"github.com/chauhanprateek89/maskplan/internal/scan"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

func TestGenerators(t *testing.T) {
	g := &gen{r: newRand(7)}
	for range 1000 {
		if v := g.iban(g.pick("IE", "GB", "DE", "FR", "NL")); !classify.IsIBAN(v) || !classify.IsIBAN(printed(v)) {
			t.Fatalf("invalid IBAN %s", v)
		}
		if v := g.pan(); !classify.IsCardNumber(v) {
			t.Fatalf("invalid card number %s", v)
		}
		if v := g.mobile(); !classify.IsPhone(v) || len(token.Normalize(token.Phone, v)) < 9 {
			t.Fatalf("invalid mobile %s", v)
		}
	}
	// Known PPSN: 1234567T (1*8+2*7+3*6+4*5+5*4+6*3+7*2 = 112, 112 mod 23 = 20, T).
	sum := 0
	for i, d := range "1234567" {
		sum += int(d-'0') * (8 - i)
	}
	if sum%23 != 20 || string(rune('A'+sum%23-1)) != "T" {
		t.Fatalf("PPSN check letter arithmetic: %d", sum%23)
	}
}

// TestAccuracyPostgres is the classifier's accuracy gate: recall of at least
// 0.95 for email, IBAN, card number and phone, at 100, 1,000 and 10,000
// sampled rows per table. Precision and the other labels are logged.
func TestAccuracyPostgres(t *testing.T) {
	dsn := os.Getenv("MASKPLAN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("MASKPLAN_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if err := Load(ctx, conn, "../../testdata/fintech/schema.sql", Options{Customers: 10000}); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(ctx, "DROP SCHEMA fintech CASCADE")
	truth, err := accuracy.LoadTruth("../../testdata/fintech/labels.yaml")
	if err != nil {
		t.Fatal(err)
	}
	gated := []string{classify.Email, classify.IBAN, classify.CardNumber, classify.Phone}
	for _, n := range []int{100, 1000, 10000} {
		f, err := scan.Postgres(ctx, conn, scan.Options{Schemas: truth.Schemas, SampleRows: n})
		if err != nil {
			t.Fatal(err)
		}
		s := accuracy.Compare(truth, f)
		var b strings.Builder
		s.WriteTable(&b)
		for _, e := range s.Errors {
			b.WriteString("  " + e.Column + ": want " + e.Want + ", got " + e.Got + " (" + e.Evidence + ")\n")
		}
		t.Logf("sample %d rows per table:\n%s", n, b.String())
		for _, l := range gated {
			if r := s.Labels[l].Recall(); r < 0.95 {
				t.Errorf("sample %d: recall for %s is %.2f, want at least 0.95", n, l, r)
			}
		}
	}
}
