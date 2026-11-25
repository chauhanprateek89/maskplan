package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The usage text and the package comment list every flag each command
// accepts, and no other. A command's real flags are read from its -h
// output, which the flag package prints from the registered flag set.
func TestUsageListsEveryFlag(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	var doc []string
	for _, line := range strings.Split(string(src), "\n") {
		if l, ok := strings.CutPrefix(line, "//\tmaskplan "); ok {
			doc = append(doc, l)
		}
	}
	var listed []string
	for _, line := range strings.Split(usage, "\n") {
		if l, ok := strings.CutPrefix(line, "  maskplan "); ok {
			listed = append(listed, l)
		} else if strings.HasPrefix(line, "   ") && len(listed) > 0 {
			listed[len(listed)-1] += " " + strings.TrimSpace(line) // a continued line
		}
	}
	flagRe := regexp.MustCompile(`--([a-z-]+)`)
	defRe := regexp.MustCompile(`(?m)^  -([a-z-]+)`)
	for _, cmd := range []string{"scan", "report", "init", "plan", "apply", "destroy"} {
		var out, errOut bytes.Buffer
		if code := run([]string{cmd, "-h"}, &out, &errOut); code != 0 {
			t.Fatalf("%s -h: exit %d", cmd, code)
		}
		var real []string
		for _, m := range defRe.FindAllStringSubmatch(errOut.String(), -1) {
			real = append(real, m[1])
		}
		slices.Sort(real)
		for name, lines := range map[string][]string{"usage": listed, "package comment": doc} {
			var shown []string
			found := false
			for _, l := range lines {
				fields := strings.Fields(l)
				if len(fields) == 0 || !slices.Contains(strings.Split(fields[0], "|"), cmd) {
					continue
				}
				found = true
				for _, m := range flagRe.FindAllStringSubmatch(l, -1) {
					if !slices.Contains(shown, m[1]) {
						shown = append(shown, m[1])
					}
				}
			}
			if !found {
				t.Errorf("%s: no line for %s", name, cmd)
				continue
			}
			slices.Sort(shown)
			if !slices.Equal(shown, real) {
				t.Errorf("%s for %s lists %v; the command accepts %v", name, cmd, shown, real)
			}
		}
	}
}

// Every maskplan command shown in the README and docs exists, and every
// flag it is shown with is one that command accepts.
func TestDocsUseRealFlags(t *testing.T) {
	accepts := map[string][]string{}
	defRe := regexp.MustCompile(`(?m)^  -([a-z-]+)`)
	for _, cmd := range []string{"scan", "report", "init", "plan", "apply", "destroy"} {
		var out, errOut bytes.Buffer
		run([]string{cmd, "-h"}, &out, &errOut)
		for _, m := range defRe.FindAllStringSubmatch(errOut.String(), -1) {
			accepts[cmd] = append(accepts[cmd], m[1])
		}
	}
	files := []string{"../../README.md", "../../demo/README.md"}
	docs, err := filepath.Glob("../../docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, docs...)
	cmdRe := regexp.MustCompile("maskplan ([a-z]+)([^#`|\\n]*)")
	flagRe := regexp.MustCompile(`(?:^|\s)--([a-z-]+)`)
	shown := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range cmdRe.FindAllStringSubmatch(string(data), -1) {
			flags, ok := accepts[m[1]]
			if !ok {
				continue // prose: "maskplan replaces values", "maskplan aims to"
			}
			shown++
			for _, fm := range flagRe.FindAllStringSubmatch(m[2], -1) {
				if !slices.Contains(flags, fm[1]) {
					t.Errorf("%s: maskplan %s%s: %s has no --%s", f, m[1], m[2], m[1], fm[1])
				}
			}
		}
	}
	if shown < 10 {
		t.Errorf("found only %d documented commands; is the pattern still right?", shown)
	}
}
