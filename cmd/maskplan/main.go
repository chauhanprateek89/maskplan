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
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/report"
	"github.com/chauhanprateek89/maskplan/internal/scan"
)

const usage = `usage:
  maskplan scan   --dsn DSN [--schema a,b] [--sample N] [--out classification.yaml]
  maskplan report --dsn DSN --role ROLE [--classification classification.yaml] [--schema a,b] [--json]

DSN may also be set in MASKPLAN_DSN: postgres://..., or for MySQL 8 (scan only so far)
user:pass@tcp(host:3306)/db or mysql://user:pass@host:3306/db.
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

// resolveDSN returns the DSN to use and whether it names a MySQL server:
// either the Go driver's form (user:pass@tcp(host:3306)/db) or a URL
// (mysql://user:pass@host:3306/db), which it converts to the driver's form.
func resolveDSN(dsn string) (string, bool, error) {
	if dsn == "" {
		dsn = os.Getenv("MASKPLAN_DSN")
	}
	switch {
	case dsn == "":
		return "", false, errors.New("no database: pass --dsn or set MASKPLAN_DSN")
	case strings.HasPrefix(dsn, "mysql://"):
		u, err := url.Parse(dsn)
		if err != nil {
			return "", false, err
		}
		cfg := mysql.NewConfig()
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
		cfg.Net, cfg.Addr = "tcp", u.Host
		if u.Port() == "" {
			cfg.Addr = u.Host + ":3306"
		}
		cfg.DBName = strings.TrimPrefix(u.Path, "/")
		return cfg.FormatDSN(), true, nil
	case strings.Contains(dsn, "@tcp(") || strings.Contains(dsn, "@unix("):
		return dsn, true, nil
	}
	return dsn, false, nil
}

func connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
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
	target, isMySQL, err := resolveDSN(*dsn)
	if err != nil {
		return err
	}
	rows := *sample
	if rows == 0 {
		rows = -1 // scan.Options: negative means no sampling
	}
	opts := scan.Options{Schemas: splitList(*schemas), InternalSchema: *internal, SampleRows: rows}
	var f *classification.File
	if isMySQL {
		db, err := sql.Open("mysql", target)
		if err != nil {
			return err
		}
		defer db.Close()
		if f, err = scan.MySQL(ctx, db, opts); err != nil {
			return err
		}
	} else {
		conn, err := connect(ctx, target)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		if f, err = scan.Postgres(ctx, conn, opts); err != nil {
			return err
		}
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
	target, isMySQL, err := resolveDSN(*dsn)
	if err != nil {
		return 2, err
	}
	if isMySQL {
		return 2, errors.New("report does not support MySQL yet; scan does")
	}
	conn, err := connect(ctx, target)
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
