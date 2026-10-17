// Package vectors defines the shared cross-engine test vectors. The committed
// file testdata/vectors.json is generated from Cases by cmd/genvectors, and
// every implementation (Go, Postgres, MySQL) must reproduce it exactly.
package vectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/chauhanprateek89/maskplan/internal/token"
)

// SpecVersion identifies the token specification the vectors encode.
const SpecVersion = 1

// FakeDictionarySize is the dictionary size used for fake_index in vectors.
const FakeDictionarySize = 4096

// Case is one input to the token function.
type Case struct {
	Name       string
	Label      string
	Normalizer token.Normalizer
	Input      *string // nil means SQL NULL
	Key        []byte
	Note       string
}

// Vector is a Case together with its expected outputs, as stored in JSON.
type Vector struct {
	Name       string           `json:"name"`
	Note       string           `json:"note,omitempty"`
	Label      string           `json:"label"`
	Normalizer token.Normalizer `json:"normalizer"`
	Input      *string          `json:"input"`
	Key        string           `json:"key"`
	Token      *string          `json:"token"`
	FakeIndex  *int             `json:"fake_index"`
}

// File is the layout of testdata/vectors.json.
type File struct {
	SpecVersion        int      `json:"spec_version"`
	FakeDictionarySize int      `json:"fake_dictionary_size"`
	Vectors            []Vector `json:"vectors"`
}

func s(v string) *string { return &v }

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

var (
	key1      = seq(0x00, 32)
	key2      = seq(0x20, 32)
	keyBlock  = bytes.Repeat([]byte{0x0b}, 64)
	keyLong   = bytes.Repeat([]byte{0xaa}, 100)
	email     = "user.contact.email"
	phone     = "user.contact.phone"
	name      = "user.name"
	uniqueID  = "user.unique_id"
	longValue = strings.Repeat("José ", 2000) // 10,000 characters, 12,000 bytes, trailing space
)

// Cases are the vectors most likely to diverge between engines. Names are
// stable identifiers; tests assert relationships between them.
var Cases = []Case{
	{Name: "email_ascii", Label: email, Normalizer: token.Email, Input: s("Alice@Example.com"), Key: key1,
		Note: "baseline ASCII case folding"},
	{Name: "email_ascii_lower", Label: email, Normalizer: token.Email, Input: s("alice@example.com"), Key: key1,
		Note: "already lowercase; must equal email_ascii"},
	{Name: "email_whitespace_ends", Label: email, Normalizer: token.Email, Input: s("\t Alice@Example.com \r\n"), Key: key1,
		Note: "tab, space, CR, LF stripped from both ends; must equal email_ascii"},
	{Name: "email_non_ascii", Label: email, Normalizer: token.Email, Input: s("Émile@Example.fr"), Key: key1,
		Note: "ASCII-only folding leaves É untouched"},
	{Name: "email_non_ascii_domain", Label: email, Normalizer: token.Email, Input: s("BOB@ÉXAMPLE.COM"), Key: key1,
		Note: "normalizes to bob@Éxample.com"},
	{Name: "trim_internal_whitespace", Label: name, Normalizer: token.Trim, Input: s("a  b"), Key: key1,
		Note: "internal whitespace is not collapsed"},
	{Name: "trim_nbsp_kept", Label: name, Normalizer: token.Trim, Input: s("\u00a0x\u00a0"), Key: key1,
		Note: "no-break space is not in the trim set"},
	{Name: "trim_vertical_tab_kept", Label: name, Normalizer: token.Trim, Input: s("\vx\f"), Key: key1,
		Note: "vertical tab and form feed are not in the trim set"},
	{Name: "trim_only_whitespace", Label: name, Normalizer: token.Trim, Input: s(" \t\r\n "), Key: key1,
		Note: "normalizes to the empty string; must equal empty_string"},
	{Name: "empty_string", Label: name, Normalizer: token.Trim, Input: s(""), Key: key1,
		Note: "empty string is a value, not NULL"},
	{Name: "null", Label: name, Normalizer: token.Trim, Input: nil, Key: key1,
		Note: "NULL in, NULL out"},
	{Name: "multibyte_name", Label: name, Normalizer: token.Trim, Input: s("José María Núñez"), Key: key1,
		Note: "UTF-8 bytes hashed as given"},
	{Name: "unicode_nfc", Label: name, Normalizer: token.Trim, Input: s("café"), Key: key1,
		Note: "é as U+00E9"},
	{Name: "unicode_nfd", Label: name, Normalizer: token.Trim, Input: s("cafe\u0301"), Key: key1,
		Note: "é as e + U+0301; bytes as given, so must differ from unicode_nfc"},
	{Name: "phone_formatted", Label: phone, Normalizer: token.Phone, Input: s("+353 (0)1 234-5678"), Key: key1,
		Note: "digits only: 353012345678"},
	{Name: "phone_national", Label: phone, Normalizer: token.Phone, Input: s("01 234 5678"), Key: key1,
		Note: "digits only: 012345678; differs from phone_formatted (no E.164 in SQL)"},
	{Name: "phone_non_ascii_digits", Label: phone, Normalizer: token.Phone, Input: s("٠١٢٣"), Key: key1,
		Note: "Arabic-Indic digits are removed; normalizes to the empty string"},
	{Name: "label_collision_email", Label: email, Normalizer: token.Email, Input: s("12345"), Key: key1,
		Note: "same normalized value as label_collision_phone"},
	{Name: "label_collision_phone", Label: phone, Normalizer: token.Phone, Input: s("12345"), Key: key1,
		Note: "label prefix must make this differ from label_collision_email"},
	{Name: "long_value", Label: name, Normalizer: token.Trim, Input: s(longValue), Key: key1,
		Note: "10,000 characters, 12,000 bytes, multi-byte"},
	{Name: "integer_id", Label: uniqueID, Normalizer: token.Trim, Input: s("12345"), Key: key1,
		Note: "integers are hashed as their decimal text"},
	{Name: "decimal_scale_1", Label: uniqueID, Normalizer: token.Trim, Input: s("1.0"), Key: key1,
		Note: "decimals are hashed as text with their scale"},
	{Name: "decimal_scale_0", Label: uniqueID, Normalizer: token.Trim, Input: s("1"), Key: key1,
		Note: "must differ from decimal_scale_1"},
	{Name: "key_rotation", Label: email, Normalizer: token.Email, Input: s("Alice@Example.com"), Key: key2,
		Note: "same input as email_ascii under a new key; must differ"},
	{Name: "key_block_size", Label: email, Normalizer: token.Email, Input: s("Alice@Example.com"), Key: keyBlock,
		Note: "64-byte key: used as is"},
	{Name: "key_longer_than_block", Label: email, Normalizer: token.Email, Input: s("Alice@Example.com"), Key: keyLong,
		Note: "100-byte key: hashed to 32 bytes before padding"},
}

// Generate computes the expected outputs for every case with package token.
func Generate() File {
	f := File{SpecVersion: SpecVersion, FakeDictionarySize: FakeDictionarySize}
	for _, c := range Cases {
		f.Vectors = append(f.Vectors, Vector{
			Name:       c.Name,
			Note:       c.Note,
			Label:      c.Label,
			Normalizer: c.Normalizer,
			Input:      c.Input,
			Key:        hex.EncodeToString(c.Key),
			Token:      token.Token(c.Key, c.Label, c.Normalizer, c.Input),
			FakeIndex:  token.FakeIndex(c.Key, c.Label, c.Normalizer, c.Input, FakeDictionarySize),
		})
	}
	return f
}

// Marshal renders f exactly as committed to testdata/vectors.json.
func Marshal(f File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Load parses a vectors file.
func Load(data []byte) (File, error) {
	var f File
	err := json.Unmarshal(data, &f)
	return f, err
}
