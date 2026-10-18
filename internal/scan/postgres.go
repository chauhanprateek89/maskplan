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
	name, typ                string
	text, date, doc, canRead bool
}

type pgTable struct {
	schema, name string
	kind         byte // r, p, m or f
	populated    bool
	columns      []pgColumn
}

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
		SELECT n.nspname, c.relname, c.relkind::text, c.relispopulated, a.attname,
			format_type(a.atttypid, a.atttypmod),
			t.typcategory IN ('S', 'I') OR t.typname IN ('json', 'jsonb', 'xml'),
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
		var c pgColumn
		if err := rows.Scan(&schema, &name, &kind, &populated, &c.name, &c.typ, &c.text, &c.date, &c.doc, &c.canRead); err != nil {
			rows.Close()
			return nil, err
		}
		if n := len(tables); n == 0 || tables[n-1].schema != schema || tables[n-1].name != name {
			tables = append(tables, &pgTable{schema: schema, name: name, kind: kind[0], populated: populated})
		}
		t := tables[len(tables)-1]
		t.columns = append(t.columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, t := range tables {
		samples, note := sampleTable(ctx, tx, t, opts.sampleRows())
		for i, c := range t.columns {
			in := classify.Input{Name: c.name, DataType: c.typ, IsText: c.text && samples != nil, IsDate: c.date, IsDoc: c.doc}
			if samples != nil {
				in.Samples = samples[i]
			}
			r := classify.Classify(in)
			ev := r.Evidence
			if note != "" && c.text {
				ev = append(ev, note)
			} else if c.text && samples != nil && !c.canRead {
				ev = append(ev, "not sampled: the scanning user cannot SELECT this column")
			}
			f.Columns = append(f.Columns, classification.Column{
				Schema: t.schema, Table: t.name, Column: c.name, Type: c.typ,
				Label: r.Label, Confidence: r.Confidence, Evidence: ev,
			})
		}
	}
	return f, nil
}

// sampleTable reads up to n rows of the table's text columns. It returns one
// slice of non-NULL values per column (nil for columns not sampled), or nil
// and a note saying why nothing was sampled.
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
		if c.text && c.canRead {
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
	q := fmt.Sprintf("SELECT %s FROM %s LIMIT %d", strings.Join(exprs, ", "), pgx.Identifier{t.schema, t.name}.Sanitize(), n)
	rows, err := sp.Query(ctx, q)
	if err != nil {
		return nil, "not sampled: " + err.Error()
	}
	defer rows.Close()
	vals := make([]*string, len(exprs))
	dest := make([]any, len(exprs))
	for i := range vals {
		dest[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return nil, "not sampled: " + err.Error()
		}
		for j, v := range vals {
			if v != nil {
				out[idx[j]] = append(out[idx[j]], *v)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "not sampled: " + err.Error()
	}
	return out, ""
}
