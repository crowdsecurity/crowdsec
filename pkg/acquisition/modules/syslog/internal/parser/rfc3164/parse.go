package rfc3164

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

type RFC3164Option func(*RFC3164)

type RFC3164 struct {
	PRI       int
	Timestamp time.Time
	Hostname  string
	Tag       string
	Message   string
	PID       string
	//
	len            int
	position       int
	buf            []byte
	useCurrentYear bool //If no year is specified in the timestamp, use the current year
	strictHostname bool //If the hostname contains invalid characters or is not an IP, return an error
}

const PRI_MAX_LEN = 3

//Order is important: format with the most information must be first because we will stop on the first match
var VALID_TIMESTAMPS = []string{
	time.RFC3339,
	"Jan 2 15:04:05 2006",
	"Jan 02 15:04:05 2006",
	"Jan 2 15:04:05",
	"Jan 02 15:04:05",
}

func WithCurrentYear() RFC3164Option {
	return func(r *RFC3164) {
		r.useCurrentYear = true
	}
}

func WithStrictHostname() RFC3164Option {
	return func(r *RFC3164) {
		r.strictHostname = true
	}
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isAlphaNumeric(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

//This function is lifted from go source
//See https://github.com/golang/go/blob/master/src/net/dnsclient.go#L75
func isValidHostname(s string) bool {
	// The root domain name is valid. See golang.org/issue/45715.
	if s == "." {
		return true
	}

	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}

func isValidHostnameOrIP(hostname string) bool {
	return isValidIP(hostname) || isValidHostname(hostname)
}

func (r *RFC3164) parsePRI() error {

	pri := 0

	if r.buf[r.position] != '<' {
		return fmt.Errorf("PRI must start with '<'")
	}

	r.position++

	for r.position < r.len {
		c := r.buf[r.position]
		if c == '>' {
			r.position++
			break
		}
		if c < '0' || c > '9' {
			return fmt.Errorf("PRI must be a number")
		}
		pri = pri*10 + int(c-'0')
		r.position++
	}

	if pri > 999 {
		return fmt.Errorf("PRI must be up to 3 characters long")
	}

	if r.position == r.len && r.buf[r.position-1] != '>' {
		return fmt.Errorf("PRI must end with '>'")
	}

	r.PRI = pri
	return nil
}

func (r *RFC3164) parseTimestamp() error {
	validTs := false
	for _, layout := range VALID_TIMESTAMPS {
		tsLen := len(layout)
		if r.position+tsLen > r.len {
			continue
		}
		t, err := time.Parse(layout, string(r.buf[r.position:r.position+tsLen]))
		if err == nil {
			validTs = true
			r.Timestamp = t
			r.position += tsLen
			break
		}
	}
	if !validTs {
		return fmt.Errorf("timestamp is not valid")
	}
	if r.useCurrentYear {
		if r.Timestamp.Year() == 0 {
			r.Timestamp = time.Date(time.Now().Year(), r.Timestamp.Month(), r.Timestamp.Day(), r.Timestamp.Hour(), r.Timestamp.Minute(), r.Timestamp.Second(), r.Timestamp.Nanosecond(), r.Timestamp.Location())
		}
	}
	r.position++
	return nil
}

func (r *RFC3164) parseHostname() error {
	hostname := []byte{}
	for r.position < r.len {
		c := r.buf[r.position]
		if c == ' ' {
			r.position++
			break
		}
		hostname = append(hostname, c)
		r.position++
	}
	if r.strictHostname {
		if !isValidHostnameOrIP(string(hostname)) {
			return fmt.Errorf("hostname is not valid")
		}
	}
	if len(hostname) == 0 {
		return fmt.Errorf("hostname is empty")
	}
	r.Hostname = string(hostname)
	return nil
}

//We do not enforce tag len as quite a lot of syslog client send tags with more than 32 chars
func (r *RFC3164) parseTag() error {
	tag := []byte{}
	pid := 0
	pidEnd := false
	hasPid := false
	for r.position < r.len {
		c := r.buf[r.position]
		if !isAlphaNumeric(c) {
			break
		}
		tag = append(tag, c)
		r.position++
	}
	if len(tag) == 0 {
		return fmt.Errorf("tag is empty")
	}
	r.Tag = string(tag)

	if r.position == r.len {
		return nil
	}

	c := r.buf[r.position]
	if c == '[' {
		hasPid = true
		r.position++
		for r.position < r.len {
			c = r.buf[r.position]
			if c == ']' {
				pidEnd = true
				r.position++
				break
			}
			if c < '0' || c > '9' {
				return fmt.Errorf("pid inside tag must be a number")
			}
			pid = pid*10 + int(c-'0')
			r.position++
		}
	}

	if hasPid && !pidEnd {
		return fmt.Errorf("pid inside tag must be closed with ']'")
	}

	if hasPid {
		r.PID = strconv.Itoa(pid)
	}
	return nil
}

func (r *RFC3164) parseMessage() error {
	err := r.parseTag()
	if err != nil {
		return err
	}

	if r.position == r.len {
		return fmt.Errorf("message is empty")
	}

	c := r.buf[r.position]

	if c == ':' {
		r.position++
	}

	for {
		if r.position >= r.len {
			return fmt.Errorf("message is empty")
		}
		c := r.buf[r.position]
		if c != ' ' {
			break
		}
		r.position++
	}

	message := []byte{}

	for r.position < r.len {
		c := r.buf[r.position]
		message = append(message, c)
		r.position++
	}
	r.Message = string(message)
	return nil
}

func (r *RFC3164) Parse(message []byte) error {
	r.len = len(message)
	if r.len == 0 {
		return fmt.Errorf("message is empty")
	}
	r.buf = message

	err := r.parsePRI()
	if err != nil {
		return err
	}

	err = r.parseTimestamp()
	if err != nil {
		return err
	}

	err = r.parseHostname()
	if err != nil {
		return err
	}

	err = r.parseMessage()
	if err != nil {
		return err
	}

	return nil
}

func NewRFC3164Parser(opts ...RFC3164Option) *RFC3164 {
	r := &RFC3164{}
	for _, opt := range opts {
		opt(r)
	}
	return r
}
