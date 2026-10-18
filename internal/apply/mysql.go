package apply

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/compile"
	"github.com/chauhanprateek89/maskplan/internal/policy"
)

// MySQLState reads what compile needs from a MySQL source.
func MySQLState(ctx context.Context, db *sql.DB, internal string) (*compile.State, error) {
	if internal == "" {
		internal = compile.DefaultInternal
	}
	st := &compile.State{Tables: map[[2]string]*compile.Table{}, Roles: map[string]bool{}, Schemas: map[string]bool{}, Owned: map[[2]string]string{}}
	rows, err := db.QueryContext(ctx, `SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, DATA_TYPE
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var schema, table, dataType string
		var c compile.Column
		if err := rows.Scan(&schema, &table, &c.Name, &c.Type, &dataType); err != nil {
			rows.Close()
			return nil, err
		}
		switch dataType {
		case "date", "datetime", "timestamp":
			c.Category = "D"
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
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			into[n] = true
		}
		return rows.Err()
	}
	if err := collect("SELECT CONCAT(User, '@', Host) FROM mysql.user", st.Roles); err != nil {
		return nil, err
	}
	if err := collect("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA", st.Schemas); err != nil {
		return nil, err
	}
	var plugins int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'AWSAuthenticationPlugin' AND PLUGIN_STATUS = 'ACTIVE'").Scan(&plugins); err != nil {
		return nil, err
	}
	st.HasRdsIam = plugins > 0
	rows, err = db.QueryContext(ctx, "SELECT kind, name, identity FROM `"+internal+"`.objects")
	var myErr *mysql.MySQLError
	switch {
	case errors.As(err, &myErr) && (myErr.Number == 1146 || myErr.Number == 1049): // first apply
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

// PlanMySQL reads the source and compiles the policy for it.
func PlanMySQL(ctx context.Context, db *sql.DB, p *policy.Policy, source string, cls *classification.File, key []byte, passwords map[string]string, internal string) (*compile.Plan, error) {
	st, err := MySQLState(ctx, db, internal)
	if err != nil {
		return nil, err
	}
	return compile.MySQL(p, source, cls, st, key, passwords, internal)
}

// PlanDestroyMySQL plans the removal of what apply created.
func PlanDestroyMySQL(ctx context.Context, db *sql.DB, internal string) (*compile.Plan, error) {
	st, err := MySQLState(ctx, db, internal)
	if err != nil {
		return nil, err
	}
	return compile.DestroyMySQL(st, internal), nil
}

// RunMySQL runs a plan statement by statement on one connection. MySQL
// commits DDL as it goes, so there is no single transaction; a plan that
// fails part way is finished by running apply again.
func RunMySQL(ctx context.Context, db *sql.DB, plan *compile.Plan) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for i, s := range plan.Statements {
		if _, err := conn.ExecContext(ctx, s.SQL, s.Args...); err != nil {
			shown := s.SQL
			if s.Display != "" {
				shown = s.Display
			}
			return fmt.Errorf("statement %d of %d: %w\n%s", i+1, len(plan.Statements), err, shown)
		}
	}
	return nil
}
