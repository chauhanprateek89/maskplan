package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func TestNormalize(t *testing.T) {
	cases := []struct {
		n    Normalizer
		in   string
		want string
	}{
		{Trim, "  a  b \t\r\n", "a  b"},
		{Trim, "\u00a0x\u00a0", "\u00a0x\u00a0"}, // NBSP is not in the trim set
		{Trim, "\v x \f", "\v x \f"},             // vertical tab and form feed are kept
		{Email, " Alice@Example.COM\n", "alice@example.com"},
		{Email, "Émile@Example.fr", "Émile@example.fr"}, // non-ASCII letters untouched
		{Email, "already@lower.case", "already@lower.case"},
		{Phone, "+353 (0)1 234-5678", "353012345678"},
		{Phone, "٣٥٣", ""}, // Arabic-Indic digits are not ASCII digits
		{Trim, "", ""},
		{Trim, " \t\r\n ", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.n, c.in); got != c.want {
			t.Errorf("Normalize(%s, %q) = %q, want %q", c.n, c.in, got, c.want)
		}
	}
}

// RFC 4231 test case 2 checks that the pads construction is plain HMAC-SHA256.
func TestPadsConstructionRFC4231(t *testing.T) {
	key := []byte("Jefe")
	msg := []byte("what do ya want for nothing?")
	want := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if got := hex.EncodeToString(hmacViaPads(key, msg)); got != want {
		t.Fatalf("HMAC via pads = %s, want %s", got, want)
	}
}

func hmacViaPads(key, msg []byte) []byte {
	ipad, opad := Pads(key)
	inner := sha256.Sum256(append(append([]byte{}, ipad...), msg...))
	outer := sha256.Sum256(append(append([]byte{}, opad...), inner[:]...))
	return outer[:]
}

// The SQL implementations compute HMAC from precomputed pads; that must equal
// crypto/hmac for short keys, block-size keys and keys longer than a block.
func TestPadsMatchHMAC(t *testing.T) {
	for _, n := range []int{1, 32, 63, 64, 65, 100, 200} {
		key := bytes.Repeat([]byte{0xab}, n)
		got := hmacViaPads(key, Message("user.contact.email", "a@b.c"))
		want := MAC(key, "user.contact.email", "a@b.c")
		if !bytes.Equal(got, want) {
			t.Errorf("key length %d: pads construction differs from crypto/hmac", n)
		}
	}
}

func TestTokenNullAndShape(t *testing.T) {
	key := []byte("k")
	if Token(key, "user.name", Trim, nil) != nil {
		t.Fatal("NULL input must give NULL token")
	}
	tok := *Token(key, "user.name", Trim, ptr("x"))
	if !strings.HasPrefix(tok, Prefix) || len(tok) != len(Prefix)+TokenHexLen {
		t.Fatalf("unexpected token shape %q", tok)
	}
	if *Token(key, "user.name", Trim, ptr(" x ")) != tok {
		t.Fatal("trimmed and untrimmed inputs must match")
	}
}

func TestLabelSeparatesDomains(t *testing.T) {
	key := []byte("k")
	a := *Token(key, "user.contact.email", Trim, ptr("12345"))
	b := *Token(key, "user.contact.phone", Trim, ptr("12345"))
	if a == b {
		t.Fatal("same value under different labels must give different tokens")
	}
}

func TestFakeIndexRange(t *testing.T) {
	key := []byte("k")
	for _, v := range []string{"a", "b", "José María Núñez", ""} {
		i := *FakeIndex(key, "user.name", Trim, ptr(v), 4096)
		if i < 0 || i >= 4096 {
			t.Fatalf("index %d out of range", i)
		}
	}
	if FakeIndex(key, "user.name", Trim, nil, 4096) != nil {
		t.Fatal("NULL input must give NULL index")
	}
}

func TestValidateLabel(t *testing.T) {
	for _, ok := range []string{"user.contact.email", "user.unique_id", "x"} {
		if err := ValidateLabel(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "User.Email", "a:b", "a..b", "a.b.", "x'; drop table t; --"} {
		if ValidateLabel(bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
