package vectors

import (
	"bytes"
	"os"
	"testing"
)

const committedPath = "../../testdata/vectors.json"

func TestCommittedFileIsUpToDate(t *testing.T) {
	want, err := Marshal(Generate())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/vectors.json is stale; run: go run ./cmd/genvectors")
	}
}

func byName(t *testing.T) map[string]Vector {
	t.Helper()
	m := map[string]Vector{}
	for _, v := range Generate().Vectors {
		if _, dup := m[v.Name]; dup {
			t.Fatalf("duplicate vector name %q", v.Name)
		}
		m[v.Name] = v
	}
	return m
}

func tok(t *testing.T, m map[string]Vector, name string) string {
	t.Helper()
	v, ok := m[name]
	if !ok {
		t.Fatalf("no vector %q", name)
	}
	if v.Token == nil {
		t.Fatalf("vector %q has a NULL token", name)
	}
	return *v.Token
}

// The relationships below are what the cases exist to prove.
func TestRelationships(t *testing.T) {
	m := byName(t)
	same := [][2]string{
		{"email_ascii", "email_ascii_lower"},
		{"email_ascii", "email_whitespace_ends"},
		{"trim_only_whitespace", "empty_string"},
	}
	for _, p := range same {
		if tok(t, m, p[0]) != tok(t, m, p[1]) {
			t.Errorf("%s and %s must have the same token", p[0], p[1])
		}
	}
	different := [][2]string{
		{"unicode_nfc", "unicode_nfd"},
		{"phone_formatted", "phone_national"},
		{"label_collision_email", "label_collision_phone"},
		{"decimal_scale_1", "decimal_scale_0"},
		{"email_ascii", "key_rotation"},
		{"email_ascii", "key_block_size"},
		{"email_ascii", "key_longer_than_block"},
	}
	for _, p := range different {
		if tok(t, m, p[0]) == tok(t, m, p[1]) {
			t.Errorf("%s and %s must have different tokens", p[0], p[1])
		}
	}
	extends := [][2]string{{"email_ascii", "token_length_24"}, {"token_length_24", "token_length_64"}}
	for _, p := range extends {
		if short, long := tok(t, m, p[0]), tok(t, m, p[1]); len(long) <= len(short) || long[:len(short)] != short {
			t.Errorf("%s must extend %s", p[1], p[0])
		}
	}
	if m["null"].Token != nil || m["null"].FakeIndex != nil {
		t.Error("null vector must have NULL outputs")
	}
}
