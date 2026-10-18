package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/chauhanprateek89/maskplan/internal/apply"
	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/report"
)

// runApply runs plan, apply and destroy. plan prints what apply would do
// and changes nothing. apply prints the same, runs it with --yes, and then
// reports on every identity with the policy: it exits 1 if any report
// fails. destroy drops what apply created.
func runApply(cmd string, args []string, stdout, stderr io.Writer) (int, error) {
	fl := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fl.SetOutput(stderr)
	policyPath := fl.String("policy", "maskplan.yaml", "policy file")
	only := fl.String("source", "", "only this source (default: every source in the policy)")
	internal := fl.String("internal-schema", compile.DefaultInternal, "maskplan's own schema")
	yes := false
	if cmd != "plan" {
		fl.BoolVar(&yes, "yes", false, "make the changes; without it, only print them")
	}
	if err := fl.Parse(args); err != nil {
		return 2, err
	}
	if fl.NArg() > 0 {
		return 2, fmt.Errorf("unexpected argument %q", fl.Arg(0))
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return 2, err
	}
	// The key and passwords are needed to change anything. plan only shows
	// SQL, which never contains them, so it runs without them.
	key, err := policy.Env(p.Key)
	if err != nil && (cmd == "apply" && yes) {
		return 2, fmt.Errorf("key: %w", err)
	} else if err != nil {
		key = rand.Text()
	}
	sources := make([]string, 0, len(p.Sources))
	for name := range p.Sources {
		if *only == "" || name == *only {
			sources = append(sources, name)
		}
	}
	if len(sources) == 0 {
		return 2, fmt.Errorf("policy has no source %q", *only)
	}
	sort.Strings(sources)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	code := 0
	for _, name := range sources {
		src := p.Sources[name]
		if src.Engine != "postgres" {
			return 2, fmt.Errorf("source %s: apply supports postgres sources only, so far", name)
		}
		dsn, err := policy.Env(src.DSN)
		if err != nil {
			return 2, fmt.Errorf("source %s: %w", name, err)
		}
		conn, err := connect(ctx, dsn)
		if err != nil {
			return 2, fmt.Errorf("source %s: %w", name, err)
		}
		defer conn.Close(ctx)
		var plan *compile.Plan
		var cls *classification.File
		if cmd == "destroy" {
			if plan, err = apply.PlanDestroyPostgres(ctx, conn, *internal); err != nil {
				return 2, fmt.Errorf("source %s: %w", name, err)
			}
			plan.Source = name
		} else {
			clsPath := src.Classification
			if !filepath.IsAbs(clsPath) {
				clsPath = filepath.Join(filepath.Dir(*policyPath), clsPath)
			}
			if cls, err = classification.Load(clsPath); err != nil {
				return 2, fmt.Errorf("source %s: %w", name, err)
			}
			passwords := map[string]string{}
			for id, ident := range p.Identities {
				if ident.Login != "password" {
					continue
				}
				pw, err := policy.Env(ident.Password)
				if err != nil && yes {
					return 2, fmt.Errorf("identity %s: %w", id, err)
				} else if err != nil {
					pw = rand.Text()
				}
				passwords[id] = pw
			}
			if plan, err = apply.PlanPostgres(ctx, conn, p, name, cls, []byte(key), passwords, *internal); err != nil {
				return 2, fmt.Errorf("source %s: %w", name, err)
			}
		}
		plan.Print(stdout)
		if !yes {
			if cmd != "plan" {
				fmt.Fprintf(stdout, "\n-- nothing changed: run maskplan %s --yes to make these changes\n", cmd)
			}
			continue
		}
		if err := apply.RunPostgres(ctx, conn, plan); err != nil {
			return 2, fmt.Errorf("source %s: %w", name, err)
		}
		fmt.Fprintf(stdout, "\n-- source %s: %s done\n", name, cmd)
		if cmd == "destroy" {
			continue
		}
		// Check what was just built, the way an auditor would.
		for _, id := range identitiesOf(p, name) {
			r, err := report.Postgres(ctx, conn, id, cls, report.Options{InternalSchema: *internal, Policy: p, Source: name})
			if err != nil {
				return 2, fmt.Errorf("report on %s: %w", id, err)
			}
			fmt.Fprintf(stdout, "\n")
			r.WriteText(stdout)
			if r.Failed() {
				code = 1
			}
		}
	}
	if code != 0 {
		fmt.Fprintln(stderr, "maskplan: a report after apply fails: see above")
	}
	return code, nil
}

func identitiesOf(p *policy.Policy, source string) []string {
	var out []string
	for name, id := range p.Identities {
		for _, s := range id.Sources {
			if s == source {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
