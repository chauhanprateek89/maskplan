package scan

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
)

// mysqlSystemSchemas are never scanned.
var mysqlSystemSchemas = []string{"mysql", "information_schema", "performance_schema", "sys"}

// MySQL scans a MySQL 8 server in a read-only transaction. Schemas are
// databases; with none given, the connection's default database is
// scanned, or every non-system database if it has none. Views are skipped,
// as on Postgres: their columns come from the tables scanned.
func MySQL(ctx context.Context, db *sql.DB, opts Options) (*classification.File, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Bounds every SELECT this session runs, sampling included; the
	// connection goes back to the caller's pool without the limit.
	if _, err := conn.ExecContext(ctx, "SET SESSION MAX_EXECUTION_TIME = 60000"); err != nil {
		return nil, err
	}
	defer conn.ExecContext(context.Background(), "SET SESSION MAX_EXECUTION_TIME = DEFAULT")
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	f := &classification.File{Version: classification.Version, Source: classification.Source{Engine: "mysql", ScannedAt: time.Now().UTC().Truncate(time.Second)}}
	var current sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&current); err != nil {
		return nil, err
	}
	f.Source.Database = current.String
	schemas := opts.Schemas
	if len(schemas) == 0 && current.Valid {
		schemas = []string{current.String}
	}

	q := `SELECT c.TABLE_SCHEMA, c.TABLE_NAME, COALESCE(t.TABLE_ROWS, 0), c.COLUMN_NAME, c.COLUMN_TYPE, c.DATA_TYPE,
			(SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE k WHERE k.TABLE_SCHEMA = c.TABLE_SCHEMA
				AND k.TABLE_NAME = c.TABLE_NAME AND k.CONSTRAINT_NAME = 'PRIMARY'),
			c.COLUMN_KEY = 'PRI'
		FROM information_schema.COLUMNS c
		JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
		WHERE t.TABLE_TYPE = 'BASE TABLE' AND c.TABLE_SCHEMA NOT IN (?, ?, ?, ?) AND c.TABLE_SCHEMA <> ?`
	args := []any{mysqlSystemSchemas[0], mysqlSystemSchemas[1], mysqlSystemSchemas[2], mysqlSystemSchemas[3], opts.internal()}
	if len(schemas) > 0 {
		q += " AND c.TABLE_SCHEMA IN (?" + strings.Repeat(", ?", len(schemas)-1) + ")"
		for _, s := range schemas {
			args = append(args, s)
		}
	}
	q += " ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION"
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var tables []*table
	pks := map[*table]string{} // single-column integer primary key, if any
	for rows.Next() {
		var schema, name, colType, dataType string
		var est float64
		var pkCols int
		var isPK bool
		var c column
		if err := rows.Scan(&schema, &name, &est, &c.name, &colType, &dataType, &pkCols, &isPK); err != nil {
			rows.Close()
			return nil, err
		}
		c.typ = colType
		mysqlCategory(&c, strings.ToLower(dataType), strings.ToLower(colType))
		c.canRead = true // information_schema lists only columns the user has privileges on
		c.sample = c.text || c.numeric && numericLabels[classify.ByName(c.name)]
		if n := len(tables); n == 0 || tables[n-1].schema != schema || tables[n-1].name != name {
			tables = append(tables, &table{schema: schema, name: name, kind: 'r', rows: est, populated: true})
		}
		t := tables[len(tables)-1]
		t.columns = append(t.columns, c)
		if isPK && pkCols == 1 && c.category == "N" && !strings.Contains(dataType, "dec") && dataType != "float" && dataType != "double" {
			pks[t] = c.name
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, t := range tables {
		start := len(f.Columns)
		samples, note := sampleMySQL(ctx, tx, t, pks[t], opts.sampleRows())
		for i, c := range t.columns {
			in := classify.Input{Name: c.name, Table: t.name, DataType: c.typ, Category: c.category,
				IsText: c.sample && samples != nil, IsDate: c.date, IsDoc: c.doc}
			if samples != nil {
				in.Samples = samples[i]
			}
			r := classify.Classify(in)
			ev := r.Evidence
			if c.sample && note != "" {
				ev = append(ev, note)
			}
			f.Columns = append(f.Columns, classification.Column{
				Schema: t.schema, Table: t.name, Column: c.name, Type: c.typ,
				Label: r.Label, Confidence: r.Confidence, Evidence: ev,
			})
		}
		markDerived(f.Columns[start:])
	}
	return f, nil
}

// mysqlCategory maps a MySQL type to the Postgres-style type category the
// classifier uses: S string, N number, D date and time, B boolean.
func mysqlCategory(c *column, dataType, colType string) {
	switch {
	case colType == "tinyint(1)" || colType == "bit(1)":
		c.category = "B"
	case dataType == "json":
		c.category, c.text, c.doc = "U", true, true
	case strings.Contains(dataType, "char") || strings.HasSuffix(dataType, "text") || dataType == "enum" || dataType == "set":
		c.category, c.text = "S", true
	case strings.Contains(dataType, "int") || dataType == "decimal" || dataType == "float" || dataType == "double":
		c.category, c.numeric = "N", true
	case dataType == "date" || dataType == "datetime" || dataType == "timestamp":
		c.category, c.date = "D", true
	case dataType == "time" || dataType == "year":
		c.category = "D"
	default: // binary, blobs, geometry
		c.category = "X"
	}
}

// sampleMySQL reads up to about n rows of the table's sampled columns.
// MySQL has no TABLESAMPLE. Tables up to 100n rows (by the server's
// estimate) are sampled with ORDER BY RAND and a fixed seed, which MySQL
// serves with a top-N sort in one pass. Larger tables with a single integer
// primary key are read in ten evenly spaced key ranges. Other large tables
// are filtered with RAND in one pass, without a sort; if that exceeds the
// statement time limit they are read from the start, and the note says so.
func sampleMySQL(ctx context.Context, tx *sql.Tx, t *table, pk string, n int) ([][]string, string) {
	if n == 0 {
		return nil, ""
	}
	var exprs []string
	var idx []int
	for i, c := range t.columns {
		if c.sample {
			limit := sampledValueBytes
			if c.doc {
				limit = sampledDocumentBytes
			}
			exprs = append(exprs, fmt.Sprintf("LEFT(CAST(%s AS CHAR), %d)", quoteMySQL(c.name), limit))
			idx = append(idx, i)
		}
	}
	out := make([][]string, len(t.columns))
	if len(exprs) == 0 {
		return out, ""
	}
	from := quoteMySQL(t.schema) + "." + quoteMySQL(t.name)
	cols := strings.Join(exprs, ", ")
	read := func(q string, args ...any) (int, error) {
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		vals := make([]sql.NullString, len(exprs))
		dest := make([]any, len(exprs))
		for i := range vals {
			dest[i] = &vals[i]
		}
		got := 0
		for rows.Next() {
			if err := rows.Scan(dest...); err != nil {
				return got, err
			}
			got++
			for j, v := range vals {
				if v.Valid {
					out[idx[j]] = append(out[idx[j]], v.String)
				}
			}
		}
		return got, rows.Err()
	}
	switch {
	case t.rows > 100*float64(n) && pk != "":
		var lo, hi sql.NullInt64
		if err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT MIN(%[1]s), MAX(%[1]s) FROM %[2]s", quoteMySQL(pk), from)).Scan(&lo, &hi); err != nil {
			return nil, "not sampled: " + err.Error()
		}
		const ranges = 10
		got := 0
		for i := range ranges {
			start := lo.Int64 + (hi.Int64-lo.Int64)/ranges*int64(i)
			k, err := read(fmt.Sprintf("SELECT %s FROM %s WHERE %s >= ? ORDER BY %s LIMIT %d", cols, from, quoteMySQL(pk), quoteMySQL(pk), (n+ranges-1)/ranges), start)
			if err != nil {
				return nil, "not sampled: " + err.Error()
			}
			got += k
		}
		return out, fmt.Sprintf("sampled %d rows from %d evenly spaced ranges of the primary key, of about %.0f", got, ranges, t.rows)
	case t.rows > float64(n) && t.rows <= 100*float64(n):
		got, err := read(fmt.Sprintf("SELECT %s FROM %s ORDER BY RAND(0) LIMIT %d", cols, from, n))
		if err != nil {
			return nil, "not sampled: " + err.Error()
		}
		return out, fmt.Sprintf("sampled %d rows at random (ORDER BY RAND) of about %.0f", got, t.rows)
	}
	if t.rows > 100*float64(n) {
		pct := 150 * float64(n) / t.rows
		got, err := read(fmt.Sprintf("SELECT %s FROM %s WHERE RAND(0) < %g LIMIT %d", cols, from, pct/100, 2*n))
		if err == nil && got > 0 {
			return out, fmt.Sprintf("sampled %d rows at random (WHERE RAND() < %.3g%%) of about %.0f", got, pct, t.rows)
		}
		for i := range out {
			out[i] = nil
		}
	}
	got, err := read(fmt.Sprintf("SELECT %s FROM %s LIMIT %d", cols, from, n+1))
	if err != nil {
		return nil, "not sampled: " + err.Error()
	}
	if got <= n {
		return out, fmt.Sprintf("sampled all %d rows", got)
	}
	for i := range out {
		if len(out[i]) > n {
			out[i] = out[i][:n]
		}
	}
	if t.rows > 100*float64(n) {
		return out, fmt.Sprintf("sampled the first %d rows, not a random sample: a random pass over the table failed or found nothing", n)
	}
	return out, fmt.Sprintf("sampled the first %d rows, not a random sample: table statistics are missing or out of date; run ANALYZE TABLE and scan again", n)
}

func quoteMySQL(id string) string { return "`" + strings.ReplaceAll(id, "`", "``") + "`" }
