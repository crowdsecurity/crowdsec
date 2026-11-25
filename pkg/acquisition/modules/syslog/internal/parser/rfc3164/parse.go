package rfc3164

import (
	"errors"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/utils"
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
	"Jan 02 15:04:05 2006",
	"Jan _2 15:04:05 2006",
	"Jan 02 15:04:05",
	"Jan _2 15:04:05",
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

func (r *RFC3164) parsePRI() error {
	pri := 0

	if r.buf[r.position] != '<' {
		return errors.New("PRI must start with '<'")
	}

	r.position++

	for r.position < r.len {
		c := r.buf[r.position]
		if c == '>' {
			r.position++
			break
		}
		if c < '0' || c > '9' {
			return errors.New("PRI must be a number")
		}
		pri = pri*10 + int(c-'0')
		r.position++
	}

	if pri > 999 {
		return errors.New("PRI must be up to 3 characters long")
	}

	if r.position == r.len && r.buf[r.position-1] != '>' {
		return errors.New("PRI must end with '>'")
	}

	r.PRI = pri
	return nil
}

// mayMatchTimestamp reports false only when time.Parse(layout, ts) must fail,
// so a failed parse does not allocate its error. In time.Parse, a 4-digit year
// starts with a digit and is followed by the next part of the layout.
// Each length below belongs to only one form in VALID_TIMESTAMPS.
func mayMatchTimestamp(layout string, ts []byte) bool {
	switch len(layout) {
	case len(time.RFC3339):
		return ts[4] == '-'
	case len("Jan 02 15:04:05 2006"): // and "Jan _2 15:04:05 2006"
		return ts[15] == ' ' && '0' <= ts[16] && ts[16] <= '9'
	}
	return true
}

func (r *RFC3164) parseTimestamp() error {
	validTs := false
	for _, layout := range VALID_TIMESTAMPS {
		tsLen := len(layout)
		if r.position+tsLen > r.len {
			continue
		}
		ts := r.buf[r.position : r.position+tsLen]
		if !mayMatchTimestamp(layout, ts) {
			continue
		}
		t, err := time.Parse(layout, string(ts))
		if err == nil {
			validTs = true
			r.Timestamp = t
			r.position += tsLen
			break
		}
	}
	if !validTs {
		return errors.New("timestamp is not valid")
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
		if !utils.IsValidHostnameOrIP(string(hostname)) {
			return errors.New("hostname is not valid")
		}
	}
	if len(hostname) == 0 {
		return errors.New("hostname is empty")
	}
	r.Hostname = string(hostname)
	return nil
}

//We do not enforce tag len as quite a lot of syslog client send tags with more than 32 chars
func (r *RFC3164) parseTag() error {
	tag := []byte{}
	tmpPid := []byte{}
	pidEnd := false
	hasPid := false
	for r.position < r.len {
		c := r.buf[r.position]
		if !utils.IsAlphaNumeric(c) {
			break
		}
		tag = append(tag, c)
		r.position++
	}
	if len(tag) == 0 {
		return errors.New("tag is empty")
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
				return errors.New("pid inside tag must be a number")
			}
			tmpPid = append(tmpPid, c)
			r.position++
		}
	}

	if hasPid && !pidEnd {
		return errors.New("pid inside tag must be closed with ']'")
	}

	if hasPid {
		r.PID = string(tmpPid)
	}
	return nil
}

func (r *RFC3164) parseMessage() error {
	err := r.parseTag()
	if err != nil {
		return err
	}

	if r.position == r.len {
		return errors.New("message is empty")
	}

	c := r.buf[r.position]

	if c == ':' {
		r.position++
	}

	for {
		if r.position >= r.len {
			return errors.New("message is empty")
		}
		c := r.buf[r.position]
		if c != ' ' {
			break
		}
		r.position++
	}

	message := r.buf[r.position:r.len]
	r.Message = string(message)
	return nil
}

func (r *RFC3164) Parse(message []byte) error {
	r.len = len(message)
	if r.len == 0 {
		return errors.New("message is empty")
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
