// Package dsn keeps connection-string passwords out of what maskplan prints.
// Redact masks the password in a DSN; Scrub masks it in an error that may
// quote the DSN, whatever produced the error (a URL parser, a driver, a
// server). Both work on DSNs that do not parse, since those are the ones
// errors quote.
package dsn

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Mask replaces a password.
const Mask = "***"

// The password in each DSN form: postgres:// and mysql:// URLs (user:pass@
// before the host, or ?password= in the query), the MySQL driver's
// user:pass@tcp(host)/db, and libpq's key=value (password=pass or
// password='pass').
var (
	keyValueRe = regexp.MustCompile(`(?i)\bpassword\s*=\s*('(?:[^'\\]|\\.)*'|[^\s]*)`)
	queryRe    = regexp.MustCompile(`(?i)([?&]password=)([^&#]*)`)
)

// userinfo returns where the password in "user:pass@" starts and ends in s,
// or ok false. A password may contain '@', '/' or ':' when a DSN was written
// without escaping, so the userinfo runs to the last '@' before any query.
func userinfo(s string) (start, end int, ok bool) {
	head := s
	if i := strings.Index(head, "?"); i >= 0 {
		head = head[:i]
	}
	from := 0
	if i := strings.Index(head, "://"); i >= 0 {
		from = i + len("://")
	}
	at := strings.LastIndex(head[from:], "@")
	if at < 0 {
		return 0, 0, false
	}
	colon := strings.Index(head[from:from+at], ":")
	if colon < 0 {
		return 0, 0, false
	}
	return from + colon + 1, from + at, true
}

// Redact returns s with every password in it replaced by Mask. User, host,
// port, database and options are kept, so an error stays useful.
func Redact(s string) string {
	if start, end, ok := userinfo(s); ok {
		s = s[:start] + Mask + s[end:]
	}
	s = queryRe.ReplaceAllString(s, "${1}"+Mask)
	if !strings.Contains(s, "://") {
		s = keyValueRe.ReplaceAllStringFunc(s, func(m string) string {
			i := strings.Index(m, "=")
			return m[:i+1] + Mask
		})
	}
	return s
}

// secrets returns the passwords in s in every form a message may quote:
// as written, unescaped, and escaped.
func secrets(s string) []string {
	var raw []string
	if start, end, ok := userinfo(s); ok {
		raw = append(raw, s[start:end])
	}
	for _, m := range queryRe.FindAllStringSubmatch(s, -1) {
		raw = append(raw, m[2])
	}
	if !strings.Contains(s, "://") {
		for _, m := range keyValueRe.FindAllStringSubmatch(s, -1) {
			v := m[1]
			if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
				raw = append(raw, v)
				v = strings.ReplaceAll(strings.ReplaceAll(v[1:len(v)-1], `\'`, `'`), `\\`, `\`)
			}
			raw = append(raw, v)
		}
	}
	var out []string
	for _, r := range raw {
		forms := []string{r, url.PathEscape(r), url.QueryEscape(r)}
		if u, err := url.PathUnescape(r); err == nil {
			forms = append(forms, u)
		}
		if u, err := url.QueryUnescape(r); err == nil {
			forms = append(forms, u)
		}
		for _, f := range forms {
			if f != "" && f != Mask && !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	// Longest first, so a password containing another form is masked whole.
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// Scrub returns err with the DSN s, and every form of its password,
// replaced in the message. errors.Is and errors.As still see err. A nil err
// stays nil.
func Scrub(err error, s string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	clean := msg
	if s != "" {
		clean = strings.ReplaceAll(clean, s, Redact(s))
	}
	for _, sec := range secrets(s) {
		clean = strings.ReplaceAll(clean, sec, Mask)
	}
	if clean == msg {
		return err
	}
	return &scrubbed{msg: clean, err: err}
}

type scrubbed struct {
	msg string
	err error
}

func (e *scrubbed) Error() string { return e.msg }
func (e *scrubbed) Unwrap() error { return e.err }
