// Package token is the reference implementation of the maskplan token
// specification (docs/token-spec.md). The SQL expressions generated for
// Postgres and MySQL must produce byte-identical results; the shared test
// vectors in testdata/vectors.json are generated from this package.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Normalizer selects how a value is canonicalized before hashing.
type Normalizer string

const (
	// Trim strips space, tab, CR and LF from both ends. Nothing else changes.
	Trim Normalizer = "trim"
	// Email trims, then lowercases ASCII A-Z only. Non-ASCII letters are kept as given.
	Email Normalizer = "email"
	// Phone keeps ASCII digits 0-9 only. No country inference.
	Phone Normalizer = "phone"
)

// Prefix is prepended to every token.
const Prefix = "tok_"

// TokenHexLen is the default number of hex characters of the HMAC kept in a
// token: 64 bits. By the birthday bound, n distinct values collide with
// probability about n^2 / 2^65: 3e-6 for 10^7 values, 3% for 10^9. A
// collision is a false join match, so labels with very many distinct values
// should use a longer token (see ValidateTokenHexLen).
const TokenHexLen = 16

// MaxTokenHexLen keeps the whole HMAC-SHA256 digest.
const MaxTokenHexLen = 64

// ValidateTokenHexLen reports whether n is a supported token length: an even
// number of hex characters from TokenHexLen to MaxTokenHexLen. 24 (96 bits)
// keeps the collision probability for 10^9 values near 6e-12.
func ValidateTokenHexLen(n int) error {
	if n < TokenHexLen || n > MaxTokenHexLen || n%2 != 0 {
		return fmt.Errorf("invalid token length %d: want an even number from %d to %d", n, TokenHexLen, MaxTokenHexLen)
	}
	return nil
}

// blockSize is the SHA-256 block size used for HMAC key padding.
const blockSize = 64

// trimSet is the exact set of characters stripped by Trim and Email.
const trimSet = " \t\r\n"

var labelPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

// ValidateLabel reports whether label may be used in a message. Labels are
// lowercase dotted identifiers, so they never contain the ':' separator and
// are safe to embed in SQL string literals.
func ValidateLabel(label string) error {
	if !labelPattern.MatchString(label) {
		return fmt.Errorf("invalid label %q: want lowercase dotted identifier like user.contact.email", label)
	}
	return nil
}

// ValidateNormalizer reports whether n is a known normalizer.
func ValidateNormalizer(n Normalizer) error {
	switch n {
	case Trim, Email, Phone:
		return nil
	}
	return fmt.Errorf("unknown normalizer %q", n)
}

// Normalize canonicalizes v according to n. It operates on bytes and never
// applies Unicode case folding or Unicode normalization.
func Normalize(n Normalizer, v string) string {
	switch n {
	case Trim:
		return strings.Trim(v, trimSet)
	case Email:
		return asciiLower(strings.Trim(v, trimSet))
	case Phone:
		return digitsOnly(v)
	}
	panic(fmt.Sprintf("unknown normalizer %q", n))
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func digitsOnly(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	return string(b)
}

// Message returns the bytes that are MACed: label, ':', normalized value.
func Message(label, normalized string) []byte {
	return []byte(label + ":" + normalized)
}

// MAC returns HMAC-SHA256(key, label ':' normalized).
func MAC(key []byte, label, normalized string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(Message(label, normalized))
	return m.Sum(nil)
}

// Token returns the default-length token for v, or nil when v is nil. NULL
// in, NULL out.
func Token(key []byte, label string, n Normalizer, v *string) *string {
	return TokenWithLength(key, label, n, v, TokenHexLen)
}

// TokenWithLength returns the token for v keeping hexLen hex characters of
// the MAC. It panics if hexLen fails ValidateTokenHexLen.
func TokenWithLength(key []byte, label string, n Normalizer, v *string, hexLen int) *string {
	if err := ValidateTokenHexLen(hexLen); err != nil {
		panic(err)
	}
	if v == nil {
		return nil
	}
	t := Prefix + hex.EncodeToString(MAC(key, label, Normalize(n, *v)))[:hexLen]
	return &t
}

// FakeIndex returns the dictionary index used by fake_* transforms: the first
// four bytes of the MAC as a big-endian integer, top bit cleared, modulo size.
// It returns nil when v is nil. Fake values are cosmetic and never join keys.
func FakeIndex(key []byte, label string, n Normalizer, v *string, size int) *int {
	if v == nil {
		return nil
	}
	if size <= 0 {
		panic("dictionary size must be positive")
	}
	mac := MAC(key, label, Normalize(n, *v))
	i := int(binary.BigEndian.Uint32(mac[:4])&0x7fffffff) % size
	return &i
}

// Pads returns the HMAC inner and outer padded keys, (K' xor ipad) and
// (K' xor opad), where K' is the key hashed if longer than the block size and
// zero-padded to it. The compiler stores these in the key table so SQL can
// compute HMAC with two plain SHA-256 calls:
//
//	HMAC(K, m) = SHA256(opad || SHA256(ipad || m))
func Pads(key []byte) (ipad, opad []byte) {
	k := key
	if len(k) > blockSize {
		sum := sha256.Sum256(k)
		k = sum[:]
	}
	ipad = make([]byte, blockSize)
	opad = make([]byte, blockSize)
	copy(ipad, k)
	copy(opad, k)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	return ipad, opad
}
