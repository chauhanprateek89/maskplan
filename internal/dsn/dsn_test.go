package dsn

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"postgres://bob:s3cret@db:5432/app?sslmode=require", "postgres://bob:***@db:5432/app?sslmode=require"},
		{"postgresql://bob:s3cret@db/app", "postgresql://bob:***@db/app"},
		{"mysql://bob:s3cret@db:33x06/app", "mysql://bob:***@db:33x06/app"},
		{"mysql://bob:p@ss/w:rd@db/app", "mysql://bob:***@db/app"},
		{"postgres://db/app?user=bob&password=s3cret&sslmode=disable", "postgres://db/app?user=bob&password=***&sslmode=disable"},
		{"postgres://bob@db/app", "postgres://bob@db/app"},
		{"bob:s3cret@tcp(db:3306)/app?parseTime=true", "bob:***@tcp(db:3306)/app?parseTime=true"},
		{"bob@tcp(db:3306)/app", "bob@tcp(db:3306)/app"},
		{"host=db user=bob password=s3cret dbname=app", "host=db user=bob password=*** dbname=app"},
		{"host=db password = 'se cr\\'et' dbname=app", "host=db password =*** dbname=app"},
		{"", ""},
	} {
		if got := Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScrub(t *testing.T) {
	if Scrub(nil, "postgres://bob:s3cret@db/app") != nil {
		t.Fatal("Scrub(nil) is not nil")
	}
	for _, c := range []struct{ dsn, msg string }{
		{"mysql://bob:s3cret@db:33x06/app", `parse "mysql://bob:s3cret@db:33x06/app": invalid port`},
		{"postgres://bob:p%40ss@db/app", "password p@ss rejected, p%40ss too"},
		{"host=db password='se cret'", "bad password 'se cret' or se cret"},
		{"bob:s3cret@tcp(db)/app", "dial bob:s3cret@tcp(db)/app: refused"},
	} {
		base := fmt.Errorf("wrapped: %s: %w", c.msg, fs.ErrNotExist)
		err := Scrub(base, c.dsn)
		for _, leak := range []string{"s3cret", "p@ss", "p%40ss", "se cret"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("Scrub(%q) left %q in %q", c.dsn, leak, err)
			}
		}
		if !strings.Contains(err.Error(), Mask) {
			t.Errorf("Scrub(%q) = %q, want the mask", c.dsn, err)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Scrub(%q) lost the wrapped error", c.dsn)
		}
	}
	plain := errors.New("connection refused")
	if Scrub(plain, "postgres://bob:s3cret@db/app") != plain {
		t.Error("Scrub changed an error with nothing to mask")
	}
}
