// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package migrate

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Stmt represents a scanned statement text along with its
// position in the file and associated comments group.
type Stmt struct {
	Pos      int      // statement position
	Text     string   // statement text
	Comments []string // associated comments
}

// Directive returns all directive comments with the given name.
// See: pkg.go.dev/cmd/compile#hdr-Compiler_Directives.
func (s *Stmt) Directive(name string) (ds []string) {
	for _, c := range s.Comments {
		switch {
		case strings.HasPrefix(c, "/*") && !strings.Contains(c, "\n"):
			if d, ok := directive(strings.TrimSuffix(c, "*/"), name, "/*"); ok {
				ds = append(ds, d)
			}
		default:
			for _, p := range []string{"#", "--", "-- "} {
				if d, ok := directive(c, name, p); ok {
					ds = append(ds, d)
				}
			}
		}
	}
	return
}

// Stmts provides a generic implementation for extracting SQL statements from the given file contents.
func Stmts(input string) ([]*Stmt, error) {
	var stmts []*Stmt
	l, err := newLex(input)
	if err != nil {
		return nil, err
	}
	for {
		s, err := l.stmt()
		if err == io.EOF {
			return stmts, nil
		}
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, s)
	}
}

type lex struct {
	input    string
	pos      int      // current phase position
	total    int      // total bytes scanned so far
	width    int      // size of latest rune
	delim    string   // configured delimiter
	comments []string // collected comments
}

const (
	eos          = -1
	delimiter    = ";"
	delimiterCmd = "delimiter"
)

func newLex(input string) (*lex, error) {
	l := &lex{input: input, delim: delimiter}
	if d, ok := directive(input, directiveDelimiter, directivePrefixSQL); ok {
		if err := l.setDelim(d); err != nil {
			return nil, err
		}
		parts := strings.SplitN(input, "\n", 2)
		if len(parts) == 1 {
			return nil, fmt.Errorf("no input found after delimiter %q", d)
		}
		l.input = parts[1]
	}
	return l, nil
}

func (l *lex) stmt() (*Stmt, error) {
	var (
		depth int
		text  string
	)
	l.skipSpaces()
Scan:
	for {
		switch r := l.next(); {
		case r == eos:
			switch {
			case depth > 0:
				return nil, errors.New("unclosed parentheses")
			case l.pos > 0:
				text = l.input
				break Scan
			default:
				return nil, io.EOF
			}
		case r == '(':
			depth++
		case r == ')':
			if depth == 0 {
				return nil, fmt.Errorf("unexpected ')' at position %d", l.pos)
			}
			depth--
		case r == '\'', r == '"', r == '`':
			if err := l.skipQuote(r); err != nil {
				return nil, err
			}
		// Check if the start of the statement is the MySQL DELIMITER command.
		// See https://dev.mysql.com/doc/refman/8.0/en/mysql-commands.html.
		case l.pos == 1 && len(l.input) > len(delimiterCmd) && strings.EqualFold(l.input[:len(delimiterCmd)], delimiterCmd):
			l.addPos(len(delimiterCmd) - 1)
			if err := l.delimCmd(); err != nil {
				return nil, err
			}
		// Delimiters take precedence over comments.
		case depth == 0 && strings.HasPrefix(l.input[l.pos-l.width:], l.delim):
			l.addPos(len(l.delim) - l.width)
			text = l.input[:l.pos]
			break Scan
		case r == '#':
			l.comment("#", "\n")
		case r == '-' && l.next() == '-':
			l.comment("--", "\n")
		case r == '/' && l.next() == '*':
			l.comment("/*", "*/")
		}
	}
	return l.emit(text), nil
}

func (l *lex) next() rune {
	if l.pos >= len(l.input) {
		return eos
	}
	r, w := utf8.DecodeRuneInString(l.input[l.pos:])
	l.width = w
	l.addPos(w)
	return r
}

func (l *lex) pick() rune {
	p, w := l.pos, l.width
	r := l.next()
	l.pos, l.width = p, w
	return r
}

func (l *lex) addPos(p int) {
	l.pos += p
	l.total += p
}

func (l *lex) skipQuote(quote rune) error {
	for {
		switch r := l.next(); {
		case r == eos:
			return fmt.Errorf("unclosed quote %q", quote)
		case r == '\\':
			l.next()
		case r == quote:
			return nil
		}
	}
}

func (l *lex) comment(left, right string) {
	i := strings.Index(l.input[l.pos:], right)
	// Not a comment.
	if i == -1 {
		return
	}
	// If the comment reside inside a statement, collect it.
	if l.pos != len(left) {
		l.addPos(i + len(right))
		return
	}
	l.addPos(i + len(right))
	// If we did not scan any statement characters, it
	// can be skipped and stored in the comments group.
	l.comments = append(l.comments, l.input[:l.pos])
	l.input = l.input[l.pos:]
	l.pos = 0
	// Double \n separate the comments group from the statement.
	if strings.HasPrefix(l.input, "\n\n") || right == "\n" && strings.HasPrefix(l.input, "\n") {
		l.comments = nil
	}
	l.skipSpaces()
}

func (l *lex) skipSpaces() {
	n := len(l.input)
	l.input = strings.TrimLeftFunc(l.input, unicode.IsSpace)
	l.total += n - len(l.input)
}

func (l *lex) emit(text string) *Stmt {
	s := &Stmt{Pos: l.total - len(text), Text: text, Comments: l.comments}
	l.input = l.input[l.pos:]
	l.pos = 0
	l.comments = nil
	// Trim custom delimiter.
	if l.delim != delimiter {
		s.Text = strings.TrimSuffix(s.Text, l.delim)
	}
	s.Text = strings.TrimSpace(s.Text)
	return s
}

// delimCmd checks if the scanned "DELIMITER"
// text represents an actual delimiter command.
func (l *lex) delimCmd() error {
	// A space must come after the delimiter.
	if l.pick() != ' ' {
		return nil
	}
	// Scan delimiter.
	for r := l.pick(); r != eos && r != '\n'; r = l.next() {
	}
	delim := strings.TrimSpace(l.input[len(delimiterCmd):l.pos])
	// MySQL client allows quoting delimiters.
	if strings.HasPrefix(delim, "'") && strings.HasSuffix(delim, "'") {
		delim = strings.ReplaceAll(delim[1:len(delim)-1], "''", "'")
	}
	if err := l.setDelim(delim); err != nil {
		return err
	}
	// Skip all we saw until now.
	l.emit(l.input[:l.pos])
	return nil
}

func (l *lex) setDelim(d string) error {
	if d == "" {
		return errors.New("empty delimiter")
	}
	// Unescape delimiters. e.g. "\\n" => "\n".
	l.delim = strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t").Replace(d)
	return nil
}
