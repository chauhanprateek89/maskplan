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
	"sort"
	"strings"
)

// Status classifies a finding.
type Status string

const (
	// Raw: the role can read this labeled column's real values.
	Raw Status = "RAW"
	// Masked: the role reads this labeled column only through a maskplan transform.
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

// keyRowsWarning says what a key table that does not hold exactly one row
// does to the masked views. Postgres views read the pads with scalar
// subqueries; MySQL views join the key row on id = 1 (sqlexpr.KeySource).
// apply's table holds exactly one row: id is its primary key, checked = 1.
func keyRowsWarning(d dialect, n int) string {
	switch {
	case d == dialectMySQL && n == 0:
		return "is empty: the masked views join the key row on id = 1, so they return no rows (no data is exposed, and none is served); run maskplan apply"
	case d == dialectMySQL:
		return fmt.Sprintf("has %d rows, want exactly 1: the masked views join every row with id = 1, so they repeat each row once per such key row, or return none; it is not the table apply creates", n)
	case n == 0:
		return "is empty: every token is NULL (no data is exposed, and token joins match nothing); run maskplan apply"
	}
	return fmt.Sprintf("has %d rows, want exactly 1: every query on a masked view that computes a token fails with \"more than one row returned by a subquery used as an expression\"; it is not the table apply creates", n)
}
