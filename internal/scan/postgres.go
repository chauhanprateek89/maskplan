// Package scan lists a database's columns and classifies each one from its
// name, type and a bounded sample of values. Sampled values stay in memory
// for the duration of one table and are never written anywhere.
package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/classify"
)

// Options narrows a scan.
type Options struct {
	// Schemas limits the scan to these schemas; empty means every
	// non-system schema.
	Schemas []string
	// InternalSchema is skipped; default maskplan_internal.
	InternalSchema string
	// SampleRows is how many rows are read from each table; 0 means 100,
	// negative means none (classify by name and type only).
	SampleRows int
}

func (o Options) internal() string {
	if o.InternalSchema == "" {
		return "maskplan_internal"
	}
	return o.InternalSchema
}

func (o Options) sampleRows() int {
	if o.SampleRows == 0 {
		return 100
	}
	return max(o.SampleRows, 0)
}

// sampledValueBytes bounds each sampled value; detectors need no more.
const sampledValueBytes = 256

type pgColumn struct {
	name, typ                         string
	text, numeric, date, doc, canRead bool
	sample                            bool // values are read and classified
}

type pgTable struct {
	schema, name string
	kind         byte    // r, p, m or f
	rows         float64 // planner estimate; <= 0 when unknown
	populated    bool
	columns      []pgColumn
}

// numericLabels are the labels whose values are often stored as numbers in
// older schemas. A number column is sampled only when its name suggests one
// of them: amounts and IDs look like phone numbers.
var numericLabels = map[string]bool{classify.CardNumber: true, classify.Phone: true, classify.NationalID: true}

// Postgres scans the database conn is connected to, in a read-only
// transaction. Partitions are scanned through their root table; foreign
// tables are classified by name and type only, never queried.
func Postgres(ctx context.Context, conn *pgx.Conn, opts Options) (*classification.File, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '60s'"); err != nil {
		return nil, err
	}
	f := &classification.File{Version: classification.Version, Source: classification.Source{Engine: "postgres", ScannedAt: time.Now().UTC().Truncate(time.Second)}}
	if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&f.Source.Database); err != nil {
		return nil, err
	}
	schemas := opts.Schemas
	if schemas == nil {
		schemas = []string{}
	}
	rows, err := tx.Query(ctx, `
		SELECT n.nspname, c.relname, c.relkind::text, c.relispopulated,
			CASE WHEN c.relkind = 'p' THEN (SELECT sum(x.reltuples) FROM pg_partition_tree(c.oid) pt
				JOIN pg_class x ON x.oid = pt.relid WHERE pt.isleaf AND x.reltuples > 0) ELSE c.reltuples END,
			a.attname, format_type(a.atttypid, a.atttypmod),
			t.typcategory IN ('S', 'I') OR t.typname IN ('json', 'jsonb', 'xml'),
			t.typcategory = 'N',
			t.typcategory = 'D',
			t.typname IN ('json', 'jsonb', 'xml'),
			has_column_privilege(c.oid, a.attnum, 'SELECT')
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_type t ON t.oid = CASE WHEN (SELECT typtype FROM pg_type WHERE oid = a.atttypid) = 'd'
			THEN (SELECT typbasetype FROM pg_type WHERE oid = a.atttypid) ELSE a.atttypid END
		WHERE a.attnum > 0 AND NOT a.attisdropped
			AND c.relkind IN ('r', 'p', 'm', 'f') AND NOT c.relispartition
			AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%'
			AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname <> $1
			AND (cardinality($2::text[]) = 0 OR n.nspname = ANY($2::text[]))
		ORDER BY 1, 2, a.attnum`, opts.internal(), schemas)
	if err != nil {
		return nil, err
	}
	var tables []*pgTable
	for rows.Next() {
		var schema, name, kind string
		var populated bool
		var est *float64
		var c pgColumn
		if err := rows.Scan(&schema, &name, &kind, &populated, &est, &c.name, &c.typ, &c.text, &c.numeric, &c.date, &c.doc, &c.canRead); err != nil {
			rows.Close()
			return nil, err
		}
		c.sample = c.text || c.numeric && numericLabels[classify.ByName(c.name)]
		if n := len(tables); n == 0 || tables[n-1].schema != schema || tables[n-1].name != name {
			t := &pgTable{schema: schema, name: name, kind: kind[0], populated: populated}
			if est != nil {
				t.rows = *est
			}
			tables = append(tables, t)
		}
		t := tables[len(tables)-1]
		t.columns = append(t.columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, t := range tables {
		start := len(f.Columns)
		samples, note := sampleTable(ctx, tx, t, opts.sampleRows())
		for i, c := range t.columns {
			in := classify.Input{Name: c.name, DataType: c.typ, IsText: c.sample && samples != nil, IsDate: c.date, IsDoc: c.doc}
			if samples != nil {
				in.Samples = samples[i]
			}
			r := classify.Classify(in)
			ev := r.Evidence
			switch {
			case !c.sample:
			case samples != nil && !c.canRead:
				ev = append(ev, "not sampled: the scanning user cannot SELECT this column")
			case note != "":
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

// DerivedSuffix marks a materialized token column: email_tok holds the
// tokens of email.
const DerivedSuffix = "_tok"

// markDerived labels each X_tok column of one table as a token of X, with
// X's label.
func markDerived(cols []classification.Column) {
	byName := map[string]classification.Column{}
	for _, c := range cols {
		byName[c.Column] = c
	}
	for i, c := range cols {
		src, ok := byName[strings.TrimSuffix(c.Column, DerivedSuffix)]
		if !strings.HasSuffix(c.Column, DerivedSuffix) || !ok {
			continue
		}
		cols[i].Label, cols[i].Confidence, cols[i].DerivedFrom = src.Label, src.Confidence, src.Column
		cols[i].Evidence = []string{fmt.Sprintf("token column of %s (name ends in %s); carries its label", src.Column, DerivedSuffix)}
	}
}

// sampleTable reads up to n rows of the table's sampled columns. It returns
// one slice of non-NULL values per column (nil for columns not sampled) and
// a note on how the rows were chosen; on failure it returns nil and a note
// saying why nothing was sampled.
//
// Tables with more than n rows by the planner's estimate are sampled with
// TABLESAMPLE SYSTEM, so rows come from the whole table: the first rows are
// often seed or migrated data, or NULL in columns added later. The seed is
// fixed so a rescan of unchanged data reads the same rows. Tables without
// statistics are read with LIMIT, and the note says so.
func sampleTable(ctx context.Context, tx pgx.Tx, t *pgTable, n int) ([][]string, string) {
	switch {
	case n == 0:
		return nil, ""
	case t.kind == 'f':
		return nil, "not sampled: foreign table"
	case t.kind == 'm' && !t.populated:
		return nil, "not sampled: materialized view is not populated"
	}
	var exprs []string
	var idx []int
	for i, c := range t.columns {
		if c.sample && c.canRead {
			exprs = append(exprs, fmt.Sprintf("left(%s::text, %d)", pgx.Identifier{c.name}.Sanitize(), sampledValueBytes))
			idx = append(idx, i)
		}
	}
	out := make([][]string, len(t.columns))
	if len(exprs) == 0 {
		return out, ""
	}
	sp, err := tx.Begin(ctx) // savepoint: one unreadable table must not end the scan
	if err != nil {
		return nil, "not sampled: " + err.Error()
	}
	defer sp.Rollback(ctx)
	from := pgx.Identifier{t.schema, t.name}.Sanitize()
	read := func(q string) (int, error) {
		for i := range out {
			out[i] = nil
		}
		rows, err := sp.Query(ctx, q)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		vals := make([]*string, len(exprs))
		dest := make([]any, len(exprs))
		for i := range vals {
			dest[i] = &vals[i]
		}
		got := 0
		for rows.Next() {
			if err := rows.Scan(dest...); err != nil {
				return 0, err
			}
			got++
			for j, v := range vals {
				if v != nil {
					out[idx[j]] = append(out[idx[j]], *v)
				}
			}
		}
		return got, rows.Err()
	}
	cols := strings.Join(exprs, ", ")
	if t.rows > float64(n) {
		// Pages are sampled, so ask for three times the rows needed.
		pct := min(100, 300*float64(n)/t.rows)
		got, err := read(fmt.Sprintf("SELECT %s FROM %s TABLESAMPLE SYSTEM (%g) REPEATABLE (0) LIMIT %d", cols, from, pct, n))
		if err != nil {
			return nil, "not sampled: " + err.Error()
		}
		if got > 0 {
			return out, fmt.Sprintf("sampled %d rows with TABLESAMPLE SYSTEM (%.3g%%) of about %.0f", got, pct, t.rows)
		}
	}
	got, err := read(fmt.Sprintf("SELECT %s FROM %s LIMIT %d", cols, from, n))
	switch {
	case err != nil:
		return nil, "not sampled: " + err.Error()
	case t.rows > float64(n):
		return out, fmt.Sprintf("sampled the first %d rows (LIMIT): TABLESAMPLE returned none", got)
	case got == n:
		return out, fmt.Sprintf("sampled the first %d rows (LIMIT), not a random sample: table statistics are missing or out of date; run ANALYZE and scan again", got)
	}
	return out, fmt.Sprintf("sampled all %d rows", got)
}
