package accuracy

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/chauhanprateek89/maskplan/internal/classification"
)

// Review is a hand review of a scan of a schema without full ground truth:
// every predicted positive judged (precision), and a random sample of
// predicted negatives judged (an estimate of recall). Columns are named
// table.column.
type Review struct {
	Version          int               `yaml:"version"`
	Source           string            `yaml:"source"`
	SHA256           string            `yaml:"sha256"`
	NotPersonal      []string          `yaml:"not_personal"`
	FreeTextPersonal []string          `yaml:"free_text_personal"`
	NegativeSample   []string          `yaml:"negative_sample"`
	Missed           map[string]string `yaml:"missed"`
	Gaps             []string          `yaml:"gaps"`
}

// LoadReview reads a review file.
func LoadReview(path string) (*Review, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Review
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", path, r.Version)
	}
	return &r, nil
}

// Assessment is the result of applying a review to a scan.
type Assessment struct {
	Positives, Correct int
	ByLabel            map[string][2]int // label -> {correct, labeled}
	Negatives          int               // columns the scan left as none
	Sampled, Misses    int               // sample size and misses in it, gaps excluded
	// Unjudged lists columns the scan labels now that the review never saw
	// (the review is stale), and sampled columns the scan now labels.
	Unjudged []string
}

// Assess applies r to f.
func Assess(r *Review, f *classification.File) Assessment {
	set := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	notPersonal, freeText, gaps := set(r.NotPersonal), set(r.FreeTextPersonal), set(r.Gaps)
	labels := map[string]string{}
	a := Assessment{ByLabel: map[string][2]int{}}
	for _, c := range f.Columns {
		name := c.Table + "." + c.Column
		labels[name] = c.Label
		if !c.IsPII() {
			a.Negatives++
			continue
		}
		ok := !notPersonal[name]
		if c.Label == classification.FreeText {
			ok = freeText[name]
		}
		a.Positives++
		v := a.ByLabel[c.Label]
		v[1]++
		if ok {
			a.Correct++
			v[0]++
		}
		a.ByLabel[c.Label] = v
	}
	for _, name := range r.NegativeSample {
		if l, ok := labels[name]; ok && l != classification.None {
			a.Unjudged = append(a.Unjudged, name+" (sampled as none, now "+l+")")
			continue
		}
		if gaps[name] {
			continue
		}
		a.Sampled++
		if _, ok := r.Missed[name]; ok {
			a.Misses++
		}
	}
	return a
}

// Precision of the labels the scan gave.
func (a Assessment) Precision() float64 { return float64(a.Correct) / float64(max(a.Positives, 1)) }

// Recall estimates recall from the sample, with a 95% Wilson interval: the
// sample's miss rate, scaled to all negatives, gives the false negatives.
func (a Assessment) Recall() (est, lo, hi float64) {
	if a.Sampled == 0 {
		return math.NaN(), math.NaN(), math.NaN()
	}
	p := float64(a.Misses) / float64(a.Sampled)
	plo, phi := wilson(a.Misses, a.Sampled)
	r := func(rate float64) float64 {
		fn := rate * float64(a.Negatives)
		return float64(a.Correct) / (float64(a.Correct) + fn)
	}
	return r(p), r(phi), r(plo)
}

func wilson(k, n int) (lo, hi float64) {
	const z = 1.96
	p, nf := float64(k)/float64(n), float64(n)
	c := (p + z*z/(2*nf)) / (1 + z*z/nf)
	h := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / (1 + z*z/nf)
	return max(0, c-h), min(1, c+h)
}

// WriteTable prints the assessment.
func (a Assessment) WriteTable(w io.Writer) {
	var labels []string
	for l := range a.ByLabel {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	fmt.Fprintf(w, "%-34s %7s %7s  %9s\n", "label", "correct", "labeled", "precision")
	for _, l := range labels {
		v := a.ByLabel[l]
		fmt.Fprintf(w, "%-34s %7d %7d  %9.2f\n", l, v[0], v[1], float64(v[0])/float64(v[1]))
	}
	fmt.Fprintf(w, "%-34s %7d %7d  %9.2f\n", "any personal data", a.Correct, a.Positives, a.Precision())
	est, lo, hi := a.Recall()
	fmt.Fprintf(w, "recall estimate %.2f (95%% interval %.2f to %.2f): %d misses in %d sampled of %d unlabeled columns\n",
		est, lo, hi, a.Misses, a.Sampled, a.Negatives)
	for _, u := range a.Unjudged {
		fmt.Fprintf(w, "not judged: %s\n", u)
	}
}
