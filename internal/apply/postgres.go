// Package apply reads a source's state, compiles the policy for it and runs
// the result. On Postgres everything runs in one transaction: an apply that
// fails changes nothing.
package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
)

// PostgresState reads what compile needs from a Postgres source.
func PostgresState(ctx context.Context, conn *pgx.Conn, internal string) (*compile.State, error) {
	if internal == "" {
		internal = compile.DefaultInternal
	}
	st := &compile.State{Tables: map[[2]string]*compile.Table{}, Roles: map[string]bool{}, Schemas: map[string]bool{}, Owned: map[[2]string]string{}}
	rows, err := conn.Query(ctx, `SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), t.typcategory::text
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_type t ON t.oid = a.atttypid
		WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT c.relispartition
			AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
		ORDER BY 1, 2, a.attnum`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var schema, table string
		var c compile.Column
		if err := rows.Scan(&schema, &table, &c.Name, &c.Type, &c.Category); err != nil {
			rows.Close()
			return nil, err
		}
		k := [2]string{schema, table}
		if st.Tables[k] == nil {
			st.Tables[k] = &compile.Table{Schema: schema, Name: table}
		}
		st.Tables[k].Columns = append(st.Tables[k].Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	collect := func(q string, into map[string]bool) error {
		rows, err := conn.Query(ctx, q)
		if err != nil {
			return err
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, n := range names {
			into[n] = true
		}
		return err
	}
	if err := collect("SELECT rolname FROM pg_roles", st.Roles); err != nil {
		return nil, err
	}
	if err := collect("SELECT nspname FROM pg_namespace", st.Schemas); err != nil {
		return nil, err
	}
	st.HasRdsIam = st.Roles["rds_iam"]
	var audit *string
	if err := conn.QueryRow(ctx, "SELECT current_setting('pgaudit.log', true)").Scan(&audit); err != nil {
		return nil, err
	}
	st.HasPgaudit = audit != nil
	rows, err = conn.Query(ctx, "SELECT pubname FROM pg_publication WHERE puballtables")
	if err != nil {
		return nil, err
	}
	if st.AllTablesPublish, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, err
	}
	rows, err = conn.Query(ctx, "SELECT kind, name, identity FROM "+pgx.Identifier{internal, "objects"}.Sanitize())
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr) && pgErr.Code == "42P01": // no objects table: first apply
		return st, nil
	case err != nil:
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, name, identity string
		if err := rows.Scan(&kind, &name, &identity); err != nil {
			return nil, err
		}
		st.Owned[[2]string{kind, name}] = identity
	}
	return st, rows.Err()
}

// PlanPostgres reads the source and compiles the policy for it.
func PlanPostgres(ctx context.Context, conn *pgx.Conn, p *policy.Policy, source string, cls *classification.File, key []byte, passwords map[string]string, internal string) (*compile.Plan, error) {
	st, err := PostgresState(ctx, conn, internal)
	if err != nil {
		return nil, err
	}
	return compile.Postgres(p, source, cls, st, key, passwords, internal)
}

// RunPostgres runs a plan in one transaction.
func RunPostgres(ctx context.Context, conn *pgx.Conn, plan *compile.Plan) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, s := range plan.Statements {
		if _, err := tx.Exec(ctx, s.SQL, s.Args...); err != nil {
			return fmt.Errorf("%w\n%s", err, s.SQL)
		}
	}
	return tx.Commit(ctx)
}

// PlanDestroyPostgres reads what apply created on a source and plans its
// removal.
func PlanDestroyPostgres(ctx context.Context, conn *pgx.Conn, internal string) (*compile.Plan, error) {
	st, err := PostgresState(ctx, conn, internal)
	if err != nil {
		return nil, err
	}
	return compile.DestroyPostgres(st, internal), nil
}
