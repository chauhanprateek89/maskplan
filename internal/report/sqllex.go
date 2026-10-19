package report

import (
	"strings"
)

// Expressions in findings. Findings go to CI logs and pull requests, and a
// view's expression can hold key pads written into it, or values the
// optimizer folded in from a table. So findings show no expression unless
// --show-expressions is given, and then only after a lexer has replaced
// every literal longer than maxShownLiteral characters. A regular expression
// cannot do this reliably: '' escapes, E'' strings with backslashes and
// dollar quoting all pair quotes differently. When the lexer cannot read an
// expression (a literal that never closes), nothing of it is shown.

const (
	hiddenExpr      = "<expression hidden; --show-expressions shows it>"
	unreadableExpr  = "<expression not shown: cannot be read safely>"
	maxShownLiteral = 8 // characters of content
	maxShownExpr    = 160
)

type dialect int

const (
	dialectPostgres dialect = iota
	dialectMySQL
)

// showExpr is what a finding prints for an expression.
func showExpr(show bool, d dialect, expr string) string {
	if !show {
		return hiddenExpr
	}
	r, ok := redactSQL(d, expr)
	if !ok {
		return unreadableExpr
	}
	r = strings.Join(strings.Fields(r), " ")
	if len(r) > maxShownExpr {
		r = r[:maxShownExpr-3] + "..."
	}
	return r
}

// redactSQL replaces long literals with '…' and comments with a space. It
// reports false if the text does not lex.
func redactSQL(d dialect, s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		// Comments.
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				return b.String(), true
			}
			i += j
			b.WriteByte(' ')
		case d == dialectMySQL && c == '#':
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				return b.String(), true
			}
			i += j
			b.WriteByte(' ')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end, ok := blockComment(d, s, i)
			if !ok {
				return "", false
			}
			i = end
			b.WriteByte(' ')

		// Quoted identifiers are kept: they are names, not values.
		case c == '"' && d == dialectPostgres, c == '`' && d == dialectMySQL:
			end, ok := quoted(s, i, c, false)
			if !ok {
				return "", false
			}
			b.WriteString(s[i:end])
			i = end

		// Postgres dollar quoting: $tag$ ... $tag$, tag empty or an
		// identifier. $1 is a parameter.
		case c == '$' && d == dialectPostgres && (i == 0 || !isWordByte(s[i-1])) && dollarTag(s, i) != "":
			tag := dollarTag(s, i)
			j := strings.Index(s[i+len(tag):], tag)
			if j < 0 {
				return "", false
			}
			body := s[i+len(tag) : i+len(tag)+j]
			writeLiteral(&b, "$$"+body+"$$", len(body))
			i += 2*len(tag) + j

		// String literals, with their prefixes: E'' (backslash escapes),
		// U&'', B'', X'' and N'' on Postgres; on MySQL every string and
		// "string" takes backslash escapes, and X'', B'', N'' and
		// _charset'' introducers are words before an ordinary string.
		case c == '\'' || (c == '"' && d == dialectMySQL):
			backslash := d == dialectMySQL || prefixedE(s, i)
			end, ok := quoted(s, i, c, backslash)
			if !ok {
				return "", false
			}
			writeLiteral(&b, s[i:end], end-i-2)
			i = end

		// Hexadecimal and binary numbers on MySQL: 0x..., 0b...
		case d == dialectMySQL && c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'b') && (i == 0 || !isWordByte(s[i-1])):
			j := i + 2
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			if j-i-2 > maxShownLiteral {
				b.WriteString(s[i:i+2] + "…")
			} else {
				b.WriteString(s[i:j])
			}
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), true
}

func writeLiteral(b *strings.Builder, lit string, contentLen int) {
	if contentLen > maxShownLiteral {
		b.WriteString("'…'")
		return
	}
	b.WriteString(lit)
}

// quoted returns the end of the quoted token starting at s[i] = q. A doubled
// quote is an escaped quote; with backslash, so is \q (and \\ is a
// backslash).
func quoted(s string, i int, q byte, backslash bool) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		switch {
		case backslash && s[j] == '\\':
			j++
		case s[j] == q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return 0, false
}

// prefixedE reports whether the string at s[i] is E'...' or e'...': the
// letter is directly before the quote and is not the end of a longer word.
func prefixedE(s string, i int) bool {
	if i == 0 || (s[i-1] != 'E' && s[i-1] != 'e') {
		return false
	}
	return i < 2 || !isWordByte(s[i-2])
}

func dollarTag(s string, i int) string {
	j := i + 1
	if j < len(s) && s[j] >= '0' && s[j] <= '9' {
		return "" // a parameter
	}
	for j < len(s) && (isWordByte(s[j]) && s[j] != '$') {
		j++
	}
	if j < len(s) && s[j] == '$' {
		return s[i : j+1]
	}
	return ""
}

// blockComment returns the end of a /* */ comment; Postgres nests them.
func blockComment(d dialect, s string, i int) (int, bool) {
	depth := 0
	for j := i; j+1 < len(s); j++ {
		switch {
		case s[j] == '/' && s[j+1] == '*':
			if depth == 0 || d == dialectPostgres {
				depth++
			}
			j++
		case s[j] == '*' && s[j+1] == '/':
			depth--
			j++
			if depth == 0 {
				return j + 1, true
			}
		}
	}
	return 0, false
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}
