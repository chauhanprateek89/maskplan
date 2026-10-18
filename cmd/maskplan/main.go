// Command maskplan classifies personal data in a database and reports which
// of it a role can read raw.
//
//	maskplan scan   --dsn DSN [--schema a,b] [--sample 100] [--out classification.yaml]
//	maskplan report --dsn DSN --role ROLE [--classification classification.yaml] [--schema a,b] [--json]
//
// The DSN can also come from MASKPLAN_DSN. Both commands only read: scan
// samples rows in a read-only transaction and stores no values; report reads
// the catalog and runs EXPLAIN.
//
// Exit status: 0 success (report: nothing raw reachable), 1 report found raw
// personal data, key material or paths it cannot trace, 2 error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/report"
	"github.com/chauhanprateek89/maskplan/internal/scan"
)

const usage = `usage:
  maskplan scan   --dsn DSN [--schema a,b] [--sample N] [--out classification.yaml]
  maskplan report --dsn DSN --role ROLE [--classification classification.yaml] [--schema a,b] [--json]

DSN may also be set in MASKPLAN_DSN. Only PostgreSQL 13 and later is supported so far.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "scan":
		err = runScan(args[1:], stdout, stderr)
	case "report":
		code, err = runReport(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "maskplan:", err)
		return 2
	}
	return code
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	if dsn == "" {
		dsn = os.Getenv("MASKPLAN_DSN")
	}
	switch {
	case dsn == "":
		return nil, errors.New("no database: pass --dsn or set MASKPLAN_DSN")
	case strings.HasPrefix(dsn, "mysql://") || strings.Contains(dsn, "@tcp("):
		return nil, errors.New("MySQL is not supported by scan and report yet; PostgreSQL only")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["application_name"] = "maskplan"
	return pgx.ConnectConfig(ctx, cfg)
}

func runScan(args []string, stdout, stderr io.Writer) error {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dsn := fl.String("dsn", "", "database connection string (default $MASKPLAN_DSN)")
	schemas := fl.String("schema", "", "comma-separated schemas to scan (default: all non-system schemas)")
	sample := fl.Int("sample", 100, "rows sampled per table; 0 classifies by name and type only")
	out := fl.String("out", "classification.yaml", "classification file to write; reviewed entries in it are kept")
	internal := fl.String("internal-schema", "maskplan_internal", "maskplan's own schema, skipped")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fl.Arg(0))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	rows := *sample
	if rows == 0 {
		rows = -1 // scan.Options: negative means no sampling
	}
	f, err := scan.Postgres(ctx, conn, scan.Options{Schemas: splitList(*schemas), InternalSchema: *internal, SampleRows: rows})
	if err != nil {
		return err
	}
	previous, err := classification.Load(*out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		previous = nil
	case err != nil:
		return err
	}
	f.Columns = classification.Merge(previous, f.Columns)
	if err := classification.Save(*out, f); err != nil {
		return err
	}
	tables := map[[2]string]bool{}
	pii, review, reviewed := 0, 0, 0
	for _, c := range f.Columns {
		tables[[2]string{c.Schema, c.Table}] = true
		switch {
		case c.Reviewed:
			reviewed++
		case c.Confidence < 0.9:
			review++
		}
		if c.IsPII() {
			pii++
		}
	}
	fmt.Fprintf(stdout, "%s in %s: %d labeled as personal data, %d kept as reviewed, %d to review (confidence below 0.9).\nWrote %s. Review it, set reviewed: true on checked entries, and commit it.\n",
		plural(len(f.Columns), "column"), plural(len(tables), "table"), pii, reviewed, review, *out)
	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func runReport(args []string, stdout, stderr io.Writer) (int, error) {
	fl := flag.NewFlagSet("report", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dsn := fl.String("dsn", "", "database connection string of an inspecting user (default $MASKPLAN_DSN)")
	role := fl.String("role", "", "role to report on (required)")
	clsPath := fl.String("classification", "classification.yaml", "classification file from maskplan scan")
	schemas := fl.String("schema", "", "comma-separated schemas to report on (default: all non-system schemas)")
	internal := fl.String("internal-schema", "maskplan_internal", "schema holding maskplan's key table")
	asJSON := fl.Bool("json", false, "write JSON")
	if err := fl.Parse(args); err != nil {
		return 2, err
	}
	if fl.NArg() > 0 {
		return 2, fmt.Errorf("unexpected argument %q", fl.Arg(0))
	}
	if *role == "" {
		return 2, errors.New("--role is required")
	}
	cls, err := classification.Load(*clsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return 2, fmt.Errorf("%s not found: run maskplan scan first", *clsPath)
	} else if err != nil {
		return 2, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return 2, err
	}
	defer conn.Close(ctx)
	r, err := report.Postgres(ctx, conn, *role, cls, report.Options{Schemas: splitList(*schemas), InternalSchema: *internal})
	if err != nil {
		return 2, err
	}
	if cls.Source.Database != "" && cls.Source.Database != r.Database {
		fmt.Fprintf(stderr, "maskplan: warning: %s was scanned from database %q, reporting on %q\n", *clsPath, cls.Source.Database, r.Database)
	}
	if *asJSON {
		if err := r.WriteJSON(stdout); err != nil {
			return 2, err
		}
	} else {
		r.WriteText(stdout)
	}
	if r.Failed() {
		return 1, nil
	}
	return 0, nil
}
