package compile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chauhanprateek89/maskplan/internal/classification"
	"github.com/chauhanprateek89/maskplan/internal/policy"
	"github.com/chauhanprateek89/maskplan/internal/sqlexpr"
	"github.com/chauhanprateek89/maskplan/internal/token"
)

// MySQLHost is the host part of every identity's account.
const MySQLHost = "%"

// MySQLAccount returns an identity's account, quoted.
func MySQLAccount(identity string) string {
	return fmt.Sprintf("'%s'@'%s'", identity, MySQLHost)
}

// MySQL compiles the policy for one MySQL source. On MySQL a database plays
// the part of a Postgres schema: each identity gets an account and a
// database of the same name holding its views. State.Roles holds accounts
// as user@host.
//
// MySQL runs DDL outside transactions, so a failed apply can stop half way.
// Every statement is idempotent: running apply again finishes the job.
func MySQL(p *policy.Policy, source string, cls *classification.File, st *State, key []byte, passwords map[string]string, internal string) (*Plan, error) {
	if internal == "" {
		internal = DefaultInternal
	}
	e := sqlexpr.MySQL
	q := func(parts ...string) string { return quote(e, parts...) }
	plan := &Plan{Source: source}
	labels := cls.Index()
	add := func(comment, sql string, args ...any) {
		plan.Statements = append(plan.Statements, Statement{SQL: sql, Args: args, Comment: comment})
	}
	ipad, opad := token.Pads(key)
	add("maskplan's own database: no account but the one running apply has privileges on it",
		"CREATE DATABASE IF NOT EXISTS "+q(internal))
	add("the key, as HMAC pads; views read it with their definer's rights",
		"CREATE TABLE IF NOT EXISTS "+q(internal, "key_material")+" (id smallint PRIMARY KEY CHECK (id = 1), ipad VARBINARY(64) NOT NULL, opad VARBINARY(64) NOT NULL)")
	add("written as parameters: the key never appears in SQL text, logs or this plan",
		"INSERT INTO "+q(internal, "key_material")+" VALUES (1, ?, ?) AS n ON DUPLICATE KEY UPDATE ipad = n.ipad, opad = n.opad", ipad, opad)
	add("the fake-name dictionary", "CREATE TABLE IF NOT EXISTS "+q(internal, "names")+" (i int PRIMARY KEY, name varchar(64) NOT NULL)")
	names := Names()
	args := make([]any, 0, 2*len(names))
	rows := make([]string, len(names))
	for i, n := range names {
		rows[i] = "(?, ?)"
		args = append(args, i, n)
	}
	add("", "INSERT INTO "+q(internal, "names")+" VALUES "+strings.Join(rows, ", ")+" AS n ON DUPLICATE KEY UPDATE name = n.name", args...)
	add("what apply created, so it changes and drops nothing else",
		"CREATE TABLE IF NOT EXISTS "+q(internal, "objects")+" (kind varchar(16) NOT NULL, name varchar(200) NOT NULL, identity varchar(64) NOT NULL, PRIMARY KEY (kind, name))")

	identities := make([]string, 0, len(p.Identities))
	for name, id := range p.Identities {
		for _, s := range id.Sources {
			if s == source {
				identities = append(identities, name)
			}
		}
	}
	sort.Strings(identities)
	wanted := map[[2]string]bool{}
	for _, name := range identities {
		id := p.Identities[name]
		if len(name) > 32 {
			return nil, fmt.Errorf("identity %s: MySQL user names have at most 32 characters", name)
		}
		if len(id.Rows) > 0 {
			return nil, fmt.Errorf("identity %s: rows filters are not supported on MySQL: it has no security barrier, so a session's own conditions can run on rows a view's filter excludes", name)
		}
		if id.Audit == "read" {
			return nil, fmt.Errorf("identity %s: audit read is not supported on MySQL yet; audit plugins filter by account in their own configuration", name)
		}
		tables, err := IdentityTables(p, source, name, st.Tables)
		if err != nil {
			return nil, err
		}
		if err := distinctViewNames(name, tables); err != nil {
			return nil, err
		}
		account := name + "@" + MySQLHost
		acct := MySQLAccount(name)
		if st.Roles[account] && st.Owned[[2]string{"role", account}] != name {
			return nil, fmt.Errorf("account %s already exists and maskplan did not create it; choose another identity name", acct)
		}
		if st.Schemas[name] && st.Owned[[2]string{"schema", name}] != name {
			return nil, fmt.Errorf("database %s already exists and maskplan did not create it; choose another identity name", name)
		}
		plan.Owns = append(plan.Owns, Object{"role", account, name}, Object{"schema", name, name})
		wanted[[2]string{"role", account}], wanted[[2]string{"schema", name}] = true, true
		add("identity "+name, "CREATE USER IF NOT EXISTS "+acct+" ACCOUNT LOCK")
		switch id.Login {
		case "iam":
			if !st.HasRdsIam {
				return nil, fmt.Errorf("identity %s: login iam needs the AWSAuthenticationPlugin (RDS and Aurora MySQL)", name)
			}
			add("", "ALTER USER "+acct+" IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS' ACCOUNT UNLOCK")
		case "password":
			pw := passwords[name]
			if pw == "" {
				return nil, fmt.Errorf("identity %s: empty password", name)
			}
			if strings.ContainsAny(pw, `'\`) {
				// Quoting them depends on the server's NO_BACKSLASH_ESCAPES mode.
				return nil, fmt.Errorf("identity %s: the password must not contain ' or \\ on MySQL", name)
			}
			add("MySQL rewrites this statement without the password in its logs",
				"ALTER USER "+acct+" IDENTIFIED BY '"+pw+"' ACCOUNT UNLOCK")
			plan.Statements[len(plan.Statements)-1].Display = "ALTER USER " + acct + " IDENTIFIED BY '…' ACCOUNT UNLOCK"
		default:
			add("", "ALTER USER "+acct+" ACCOUNT LOCK")
		}
		add("enforced by the server; 0 is no limit", fmt.Sprintf("ALTER USER %s WITH MAX_USER_CONNECTIONS %d", acct, id.Limits.Connections))
		if id.Limits.StatementTimeout != "" {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("identity %s: statement_timeout is not applied on MySQL, which has no per-account setting; set max_execution_time on the server or in the client", name))
		}
		add("", "CREATE DATABASE IF NOT EXISTS "+q(name))

		for _, t := range tables {
			v, sel, warnings, err := ViewSelect(e, p, source, name, t, labels, internal)
			if err != nil {
				return nil, err
			}
			plan.Warnings = append(plan.Warnings, warnings...)
			if sel == "" {
				continue
			}
			view := q(name, t.Name)
			add(fmt.Sprintf("%s reads %s.%s", name, t.Schema, t.Name),
				fmt.Sprintf("CREATE OR REPLACE SQL SECURITY DEFINER VIEW %s AS\n%s", view, sel))
			add("", fmt.Sprintf("GRANT SELECT ON %s TO %s", view, acct))
			plan.Views = append(plan.Views, v)
			plan.Owns = append(plan.Owns, Object{"view", name + "." + t.Name, name})
			wanted[[2]string{"view", name + "." + t.Name}] = true
		}
	}
	var stale []Object
	for k, identity := range st.Owned {
		if !wanted[k] {
			stale = append(stale, Object{k[0], k[1], identity})
		}
	}
	sortObjects(stale)
	for _, o := range stale {
		for i, sql := range dropMySQL(o, st) {
			comment := ""
			if i == 0 {
				comment = "no longer in the policy"
			}
			add(comment, sql)
		}
		add("", "DELETE FROM "+q(internal, "objects")+" WHERE kind = ? AND name = ?", o.Kind, o.Name)
	}
	for _, o := range plan.Owns {
		add("", "INSERT INTO "+q(internal, "objects")+" VALUES (?, ?, ?) AS n ON DUPLICATE KEY UPDATE identity = n.identity", o.Kind, o.Name, o.Identity)
	}
	return plan, nil
}

// dropMySQL drops one object. Dropping a view leaves its grants behind on
// MySQL, ready to apply to a view created later under the same name, so
// they are revoked first.
func dropMySQL(o Object, st *State) []string {
	q := func(parts ...string) string { return quote(sqlexpr.MySQL, parts...) }
	switch o.Kind {
	case "view":
		schema, view, _ := strings.Cut(o.Name, ".")
		return []string{
			fmt.Sprintf("REVOKE IF EXISTS ALL ON %s FROM %s IGNORE UNKNOWN USER", q(schema, view), MySQLAccount(o.Identity)),
			"DROP VIEW IF EXISTS " + q(schema, view),
		}
	case "schema":
		return []string{"DROP DATABASE IF EXISTS " + q(o.Name)}
	}
	user, _, _ := strings.Cut(o.Name, "@")
	return []string{"DROP USER IF EXISTS " + MySQLAccount(user)}
}

// DestroyMySQL drops everything apply created on a MySQL source.
func DestroyMySQL(st *State, internal string) *Plan {
	if internal == "" {
		internal = DefaultInternal
	}
	plan := &Plan{}
	objs := make([]Object, 0, len(st.Owned))
	for k, identity := range st.Owned {
		objs = append(objs, Object{k[0], k[1], identity})
	}
	sortObjects(objs)
	for _, o := range objs {
		for _, sql := range dropMySQL(o, st) {
			plan.Statements = append(plan.Statements, Statement{SQL: sql})
		}
	}
	plan.Statements = append(plan.Statements, Statement{SQL: "DROP DATABASE IF EXISTS " + quote(sqlexpr.MySQL, internal), Comment: "maskplan's own database and the key"})
	return plan
}
