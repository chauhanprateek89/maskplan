// Command accuracy scans a database with known ground truth at several
// sample sizes and reports the classifier's precision and recall per label.
//
//	go run ./bench/accuracy -dsn postgres://... -truth testdata/adventureworks/labels.yaml
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

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
	flag.Parse()
	truth, err := accuracy.LoadTruth(*truthPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(ctx)
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
