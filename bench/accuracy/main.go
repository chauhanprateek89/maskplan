// Command accuracy scans a database with known ground truth at several
// sample sizes and reports the classifier's precision and recall per label.
// With -review instead of -truth it applies a hand review of a schema
// without full ground truth (testdata/gitlab/review.yaml).
//
//	go run ./bench/accuracy -dsn postgres://... -truth testdata/adventureworks/labels.yaml
//	go run ./bench/accuracy -dsn postgres://.../gitlab -review testdata/gitlab/review.yaml
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/accuracy"
	"github.com/chauhanprateek89/maskplan/internal/scan"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("MASKPLAN_DSN"), "database holding the labeled schema")
	truthPath := flag.String("truth", "", "ground-truth labels file")
	samples := flag.String("sample", "100,1000,10000", "comma-separated sample sizes")
	out := flag.String("out", "", "write results as JSON to this file")
	errors := flag.Bool("errors", false, "list every misclassified column")
	reviewPath := flag.String("review", "", "hand review file, instead of -truth")
	flag.Parse()
	ctx := context.Background()
	if strings.Contains(*dsn, "@tcp(") {
		runMySQL(ctx, *dsn, *truthPath, *samples, *out, *errors)
		return
	}
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(ctx)
	if *reviewPath != "" {
		review, err := accuracy.LoadReview(*reviewPath)
		if err != nil {
			log.Fatal(err)
		}
		start := time.Now()
		f, err := scan.Postgres(ctx, conn, scan.Options{})
		if err != nil {
			log.Fatal(err)
		}
		a := accuracy.Assess(review, f)
		fmt.Printf("%s: %d columns, %.1f s\n", review.Source, len(f.Columns), time.Since(start).Seconds())
		a.WriteTable(os.Stdout)
		if *out != "" {
			est, lo, hi := a.Recall()
			data, _ := json.MarshalIndent(map[string]any{"review": *reviewPath, "source": review.Source, "sha256": review.SHA256,
				"date": time.Now().UTC().Format("2006-01-02"), "columns": len(f.Columns), "positives": a.Positives, "correct": a.Correct,
				"precision": a.Precision(), "by_label": a.ByLabel, "negatives": a.Negatives, "sampled": a.Sampled, "misses": a.Misses,
				"recall_estimate": est, "recall_interval": []float64{lo, hi}, "unjudged": a.Unjudged}, "", "  ")
			if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
				log.Fatal(err)
			}
		}
		return
	}
	truth, err := accuracy.LoadTruth(*truthPath)
	if err != nil {
		log.Fatal(err)
	}
	var version string
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version')").Scan(&version); err != nil {
		log.Fatal(err)
	}
	type run struct {
		Sample  int            `json:"sample"`
		Seconds float64        `json:"seconds"`
		Score   accuracy.Score `json:"score"`
	}
	result := struct {
		Truth    string `json:"truth"`
		Source   string `json:"source"`
		Postgres string `json:"postgres"`
		Date     string `json:"date"`
		Runs     []run  `json:"runs"`
	}{Truth: *truthPath, Source: truth.Source, Postgres: version, Date: time.Now().UTC().Format("2006-01-02")}
	for _, s := range strings.Split(*samples, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			log.Fatalf("bad sample size %q", s)
		}
		start := time.Now()
		f, err := scan.Postgres(ctx, conn, scan.Options{Schemas: truth.Schemas, SampleRows: n})
		if err != nil {
			log.Fatal(err)
		}
		sc := accuracy.Compare(truth, f)
		r := run{Sample: n, Seconds: time.Since(start).Seconds(), Score: sc}
		result.Runs = append(result.Runs, r)
		fmt.Printf("sample %d rows per table: %d columns, %.1f s\n", n, sc.Columns, r.Seconds)
		sc.WriteTable(os.Stdout)
		if *errors {
			for _, e := range sc.Errors {
				fmt.Printf("  %-55s want %-32s got %-32s %s\n", e.Column, e.Want, e.Got, e.Evidence)
			}
		}
		fmt.Println()
	}
	if *out != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

// runMySQL is the ground-truth run against MySQL (driver-form DSN).
func runMySQL(ctx context.Context, dsn, truthPath, samples, out string, listErrors bool) {
	truth, err := accuracy.LoadTruth(truthPath)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var version string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		log.Fatal(err)
	}
	type run struct {
		Sample  int            `json:"sample"`
		Seconds float64        `json:"seconds"`
		Score   accuracy.Score `json:"score"`
	}
	var runs []run
	for _, s := range strings.Split(samples, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			log.Fatalf("bad sample size %q", s)
		}
		start := time.Now()
		f, err := scan.MySQL(ctx, db, scan.Options{Schemas: truth.Schemas, SampleRows: n})
		if err != nil {
			log.Fatal(err)
		}
		sc := accuracy.Compare(truth, f)
		runs = append(runs, run{Sample: n, Seconds: time.Since(start).Seconds(), Score: sc})
		fmt.Printf("sample %d rows per table: %d columns, %.1f s\n", n, sc.Columns, time.Since(start).Seconds())
		sc.WriteTable(os.Stdout)
		if listErrors {
			for _, e := range sc.Errors {
				fmt.Printf("  %-45s want %-32s got %-32s %s\n", e.Column, e.Want, e.Got, e.Evidence)
			}
		}
		fmt.Println()
	}
	if out != "" {
		data, _ := json.MarshalIndent(map[string]any{"truth": truthPath, "source": truth.Source, "mysql": version,
			"date": time.Now().UTC().Format("2006-01-02"), "runs": runs}, "", "  ")
		if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
