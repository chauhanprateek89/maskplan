// Package accuracy scores a scan against hand-written ground truth:
// precision and recall per label, and for personal data as a whole.
package accuracy

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

// Truth is a ground-truth file. Columns lists every personal-data column;
// every other scanned column in Schemas is expected to be "none".
type Truth struct {
	Version int      `yaml:"version"`
	Source  string   `yaml:"source"`
	Schemas []string `yaml:"schemas"`
	Columns []struct {
		Schema string `yaml:"schema"`
		Table  string `yaml:"table"`
		Column string `yaml:"column"`
		Label  string `yaml:"label"`
	} `yaml:"columns"`
}

// LoadTruth reads a ground-truth file.
func LoadTruth(path string) (*Truth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Truth
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if t.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", path, t.Version)
	}
	return &t, nil
}

// Counts are true positives, false positives and false negatives.
type Counts struct {
	TP, FP, FN int
}

// Precision is TP / (TP + FP); 1 when nothing was predicted.
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}

// Recall is TP / (TP + FN); 1 when nothing was expected.
func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

// Error is one column the scan got wrong.
type Error struct {
	Column   string `json:"column"`
	Want     string `json:"want"`
	Got      string `json:"got"`
	Evidence string `json:"evidence"`
}

// Score is the result of comparing one scan with the truth.
type Score struct {
	Columns int               `json:"columns"`
	PII     Counts            `json:"pii"` // personal data at all, whatever the label
	Labels  map[string]Counts `json:"labels"`
	Errors  []Error           `json:"errors"`
}

// Compare scores a scan. A truth column the scan did not produce counts as
// a false negative.
func Compare(t *Truth, f *classification.File) Score {
	want := map[classification.Key]string{}
	for _, c := range t.Columns {
		want[classification.Key{Schema: c.Schema, Table: c.Table, Column: c.Column}] = c.Label
	}
	got := f.Index()
	s := Score{Labels: map[string]Counts{}}
	keys := map[classification.Key]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	for k := range keys {
		w, ok := want[k]
		if !ok {
			w = classification.None
		}
		g := classification.None
		ev := "not scanned"
		if c, ok := got[k]; ok {
			g, ev = c.Label, strings.Join(c.Evidence, "; ")
		}
		s.Columns++
		wp, gp := w != classification.None, g != classification.None
		switch {
		case wp && gp:
			s.PII.TP++
		case gp:
			s.PII.FP++
		case wp:
			s.PII.FN++
		}
		if w == g {
			if wp {
				c := s.Labels[w]
				c.TP++
				s.Labels[w] = c
			}
			continue
		}
		if wp {
			c := s.Labels[w]
			c.FN++
			s.Labels[w] = c
		}
		if gp {
			c := s.Labels[g]
			c.FP++
			s.Labels[g] = c
		}
		s.Errors = append(s.Errors, Error{Column: k.String(), Want: w, Got: g, Evidence: ev})
	}
	sort.Slice(s.Errors, func(i, j int) bool { return s.Errors[i].Column < s.Errors[j].Column })
	return s
}

// WriteTable prints per-label precision and recall.
func (s Score) WriteTable(w io.Writer) {
	var labels []string
	for l := range s.Labels {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	fmt.Fprintf(w, "%-34s %4s %4s %4s  %9s  %6s\n", "label", "tp", "fp", "fn", "precision", "recall")
	row := func(name string, c Counts) {
		fmt.Fprintf(w, "%-34s %4d %4d %4d  %9.2f  %6.2f\n", name, c.TP, c.FP, c.FN, c.Precision(), c.Recall())
	}
	for _, l := range labels {
		row(l, s.Labels[l])
	}
	row("any personal data", s.PII)
}
