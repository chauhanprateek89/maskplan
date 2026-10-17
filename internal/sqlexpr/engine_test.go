package sqlexpr

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/chauhanprateek89/maskplan/internal/token"
	"github.com/chauhanprateek89/maskplan/internal/vectors"
)

// These tests run every shared vector through the generated SQL on a live
// database. They are skipped unless a DSN is provided:
//
//	MASKPLAN_TEST_POSTGRES_DSN=postgres://user:pass@localhost:5432/db
//	MASKPLAN_TEST_MYSQL_DSN=user:pass@tcp(127.0.0.1:3306)/db

func loadVectors(t *testing.T) vectors.File {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := vectors.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type engineSetup struct {
	driver     string
	envDSN     string
	keyDDL     string
	valueDDL   string
	insertKey  string
	insertVal  string
	selectExpr func(tokenExpr, fakeExpr string) string
}

var setups = map[Engine]engineSetup{
	Postgres: {
		driver:    "pgx",
		envDSN:    "MASKPLAN_TEST_POSTGRES_DSN",
		keyDDL:    "CREATE TEMP TABLE vec_keys (key_id int PRIMARY KEY, ipad bytea NOT NULL, opad bytea NOT NULL)",
		valueDDL:  "CREATE TEMP TABLE vec_values (id int PRIMARY KEY, key_id int NOT NULL, input text)",
		insertKey: "INSERT INTO vec_keys VALUES ($1, $2, $3)",
		insertVal: "INSERT INTO vec_values VALUES ($1, $2, $3)",
		selectExpr: func(tok, fake string) string {
			return fmt.Sprintf("SELECT %s, %s FROM vec_values v JOIN vec_keys k ON k.key_id = v.key_id WHERE v.id = $1", tok, fake)
		},
	},
	MySQL: {
		driver:    "mysql",
		envDSN:    "MASKPLAN_TEST_MYSQL_DSN",
		keyDDL:    "CREATE TEMPORARY TABLE vec_keys (key_id int PRIMARY KEY, ipad VARBINARY(64) NOT NULL, opad VARBINARY(64) NOT NULL)",
		valueDDL:  "CREATE TEMPORARY TABLE vec_values (id int PRIMARY KEY, key_id int NOT NULL, input MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci)",
		insertKey: "INSERT INTO vec_keys VALUES (?, ?, ?)",
		insertVal: "INSERT INTO vec_values VALUES (?, ?, ?)",
		selectExpr: func(tok, fake string) string {
			return fmt.Sprintf("SELECT %s, %s FROM vec_values v JOIN vec_keys k ON k.key_id = v.key_id WHERE v.id = ?", tok, fake)
		},
	},
}

func TestVectorsPostgres(t *testing.T) { runVectors(t, Postgres) }
func TestVectorsMySQL(t *testing.T)    { runVectors(t, MySQL) }

// Real MySQL columns may use other character sets, and sessions may run with
// NO_BACKSLASH_ESCAPES. Neither may change the token.
func TestMySQLColumnCharsetAndSQLMode(t *testing.T) {
	dsn := os.Getenv(setups[MySQL].envDSN)
	if dsn == "" {
		t.Skipf("%s not set", setups[MySQL].envDSN)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	want := map[string]vectors.Vector{}
	for _, v := range loadVectors(t).Vectors {
		want[v.Name] = v
	}
	stmts := []string{
		"SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_BACKSLASH_ESCAPES')",
		"CREATE TEMPORARY TABLE cs_keys (ipad VARBINARY(64) NOT NULL, opad VARBINARY(64) NOT NULL)",
		"CREATE TEMPORARY TABLE cs_values (name VARCHAR(64), input VARCHAR(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci)",
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// All selected vectors use key1; latin1 can represent their inputs.
	names := []string{"email_ascii", "email_whitespace_ends", "email_non_ascii", "multibyte_name", "phone_formatted"}
	raw, _ := hex.DecodeString(want[names[0]].Key)
	ipad, opad := token.Pads(raw)
	if _, err := db.Exec("INSERT INTO cs_keys VALUES (?, ?)", ipad, opad); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if want[n].Key != want[names[0]].Key {
			t.Fatalf("%s uses a different key", n)
		}
		if _, err := db.Exec("INSERT INTO cs_values VALUES (?, ?)", n, *want[n].Input); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range names {
		v := want[n]
		expr, err := Token(MySQL, Column{Expr: "v.input", Label: v.Label, Normalizer: v.Normalizer}, Pads{IPad: "k.ipad", OPad: "k.opad"})
		if err != nil {
			t.Fatal(err)
		}
		var got string
		q := fmt.Sprintf("SELECT %s FROM cs_values v CROSS JOIN cs_keys k WHERE v.name = ?", expr)
		if err := db.QueryRow(q, n).Scan(&got); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if got != *v.Token {
			t.Errorf("%s from latin1 column with NO_BACKSLASH_ESCAPES: token %s, want %s", n, got, *v.Token)
		}
	}
}

func runVectors(t *testing.T, e Engine) {
	s := setups[e]
	dsn := os.Getenv(s.envDSN)
	if dsn == "" {
		t.Skipf("%s not set", s.envDSN)
	}
	db, err := sql.Open(s.driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Temporary tables are per connection, so pin one.
	db.SetMaxOpenConns(1)

	for _, ddl := range []string{s.keyDDL, s.valueDDL} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("%s: %v", ddl, err)
		}
	}

	f := loadVectors(t)
	keyIDs := map[string]int{}
	for i, v := range f.Vectors {
		id, ok := keyIDs[v.Key]
		if !ok {
			id = len(keyIDs) + 1
			keyIDs[v.Key] = id
			raw, err := hex.DecodeString(v.Key)
			if err != nil {
				t.Fatal(err)
			}
			ipad, opad := token.Pads(raw)
			if _, err := db.Exec(s.insertKey, id, ipad, opad); err != nil {
				t.Fatal(err)
			}
		}
		var input any
		if v.Input != nil {
			input = *v.Input
		}
		if _, err := db.Exec(s.insertVal, i+1, id, input); err != nil {
			t.Fatalf("insert %s: %v", v.Name, err)
		}
	}

	pads := Pads{IPad: "k.ipad", OPad: "k.opad"}
	for i, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			col := Column{Expr: "v.input", Label: v.Label, Normalizer: v.Normalizer, TokenHexLen: v.TokenHexLen}
			tokExpr, err := Token(e, col, pads)
			if err != nil {
				t.Fatal(err)
			}
			fakeExpr, err := FakeIndex(e, col, pads, f.FakeDictionarySize)
			if err != nil {
				t.Fatal(err)
			}
			var gotTok sql.NullString
			var gotFake sql.NullInt64
			if err := db.QueryRow(s.selectExpr(tokExpr, fakeExpr), i+1).Scan(&gotTok, &gotFake); err != nil {
				t.Fatal(err)
			}
			if v.Token == nil {
				if gotTok.Valid || gotFake.Valid {
					t.Fatalf("want NULL outputs, got token=%v fake=%v", gotTok, gotFake)
				}
				return
			}
			if !gotTok.Valid || gotTok.String != *v.Token {
				t.Errorf("token = %v, want %s", gotTok, *v.Token)
			}
			if !gotFake.Valid || int(gotFake.Int64) != *v.FakeIndex {
				t.Errorf("fake_index = %v, want %d", gotFake, *v.FakeIndex)
			}
		})
	}
}
