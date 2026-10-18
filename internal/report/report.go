// Package report answers, for one database role: which personal data can it
// read raw, by which privilege path, and would anyone know? It only reads the
// catalog and runs EXPLAIN; it changes nothing.
//
// The rule that shapes it: a path the report cannot trace is reported as
// UNKNOWN, never as MASKED. Saying "masked" when raw data is reachable is the
// one failure that makes the tool worse than nothing.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Status classifies a finding.
type Status string

const (
	// Raw: the role can read this labeled column's real values.
	Raw Status = "RAW"
	// Masked: the role reads this labeled column only as maskplan tokens.
	Masked Status = "MASKED"
	// Unknown: a path exists that the report cannot trace; treat as raw.
	Unknown Status = "UNKNOWN"
	// Unlabeled: the role can read a column the classification does not list.
	Unlabeled Status = "UNLABELED"
	// Key: the role can read the token key material.
	Key Status = "KEY"
	// Warn: a setting or path that does not expose data today but should be
	// reviewed (future tables, replication of the key table, ...).
	Warn Status = "WARN"
)

var (
	// sqlLiteralRe matches string literals left to right, so that each
	// match is a real literal, not the text between two of them.
	sqlLiteralRe = regexp.MustCompile(`'(?:[^'\\]|\\.|'')*'`)
	hexLiteralRe = regexp.MustCompile(`0x[0-9A-Fa-f]{17,}`)
)

// redactLiterals replaces literals long enough to be key material or data
// (over 16 characters) with '…'.
func redactLiterals(expr string) string {
	expr = sqlLiteralRe.ReplaceAllStringFunc(expr, func(l string) string {
		if len(l) > 18 {
			return "'…'"
		}
		return l
	})
	return hexLiteralRe.ReplaceAllString(expr, "0x…")
}

// printableExpr shortens an SQL expression for a finding. Findings end up in CI
// logs and pull requests, so long literals, which can hold key pads written
// into a view or values the optimizer folded in, are replaced by '…'.
func printableExpr(expr string) string {
	s := strings.Join(strings.Fields(redactLiterals(expr)), " ")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// severity orders findings in output and decides the exit code.
var severity = map[Status]int{Key: 0, Raw: 1, Unknown: 2, Unlabeled: 3, Warn: 4, Masked: 5}

// Finding is one line of the report.
type Finding struct {
	Status Status `json:"status"`
	// Object is schema.table.column for columns, or a description such as
	// "function public.f(integer)" or "role".
	Object string `json:"object"`
	Label  string `json:"label,omitempty"`
	// Path explains how the role reaches the object.
	Path string `json:"path"`
}

// Settings describes how the role is controlled and observed.
type Settings struct {
	Login            string `json:"login"`
	Audit            string `json:"audit"`
	ConnectionLimit  string `json:"connection_limit"`
	StatementTimeout string `json:"statement_timeout"`
}

// Report is the result for one role.
type Report struct {
	Role     string    `json:"role"`
	Engine   string    `json:"engine"`
	Version  string    `json:"version"`
	Database string    `json:"database"`
	Settings Settings  `json:"settings"`
	Findings []Finding `json:"findings"`
}

// Counts returns the number of findings per status.
func (r *Report) Counts() map[Status]int {
	m := map[Status]int{}
	for _, f := range r.Findings {
		m[f.Status]++
	}
	return m
}

// Failed reports whether the role can, or may, read raw personal data or key
// material. A readable column missing from the classification fails too: the
// report cannot vouch for it until it is scanned and labeled. Failed decides
// the CLI exit code.
func (r *Report) Failed() bool {
	c := r.Counts()
	return c[Raw]+c[Unknown]+c[Key]+c[Unlabeled] > 0
}

func (r *Report) sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if severity[a.Status] != severity[b.Status] {
			return severity[a.Status] < severity[b.Status]
		}
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		return a.Path < b.Path
	})
}

// WriteText renders the report for people.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "role: %s    source: %s %s, database %s\n\n", r.Role, r.Engine, r.Version, r.Database)
	width := 0
	for _, f := range r.Findings {
		width = max(width, len(f.Object))
	}
	for _, f := range r.Findings {
		label := f.Label
		if label == "" {
			label = "-"
		}
		fmt.Fprintf(w, "%-9s %-*s  %-34s %s\n", f.Status, width, f.Object, label, f.Path)
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
	}
	s := r.Settings
	fmt.Fprintf(w, "login: %s\naudit: %s\nconnection limit: %s\nstatement timeout: %s\n\n", s.Login, s.Audit, s.ConnectionLimit, s.StatementTimeout)
	c := r.Counts()
	var parts []string
	for _, st := range []Status{Key, Raw, Unknown, Unlabeled, Warn, Masked} {
		if c[st] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[st], strings.ToLower(string(st))))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no findings")
	}
	verdict := "PASS: no raw personal data or key material reachable"
	if r.Failed() {
		verdict = "FAIL: raw personal data or key material is, or may be, reachable"
	}
	fmt.Fprintf(w, "%s. %s.\n", strings.Join(parts, ", "), verdict)
}

// WriteJSON renders the report for CI.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		*Report
		Counts map[Status]int `json:"counts"`
		Failed bool           `json:"failed"`
	}{r, r.Counts(), r.Failed()})
}
