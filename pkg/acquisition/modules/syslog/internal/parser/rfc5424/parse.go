package rfc5424

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/syslog/internal/parser/utils"
)

type RFC5424Option func(*RFC5424)

type RFC5424 struct {
	PRI       int
	Timestamp time.Time
	Hostname  string
	Tag       string
	Message   string
	PID       string
	MsgID     string
	//
	len            int
	position       int
	buf            []byte
	useCurrentYear bool // If no year is specified in the timestamp, use the current year
	strictHostname bool // If the hostname contains invalid characters or is not an IP, return an error
}

const PRI_MAX_LEN = 3

const NIL_VALUE = '-'

var VALID_TIMESTAMPS = []string{
	time.RFC3339,
}

const VALID_TIMESTAMP = time.RFC3339Nano

func WithCurrentYear() RFC5424Option {
	return func(r *RFC5424) {
		r.useCurrentYear = true
	}
}

func WithStrictHostname() RFC5424Option {
	return func(r *RFC5424) {
		r.strictHostname = true
	}
}

func (r *RFC5424) parsePRI() error {

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

func (r *RFC5424) parseVersion() error {
	if r.buf[r.position] != '1' {
		return fmt.Errorf("version must be 1")
	}
	r.position += 2
	if r.position >= r.len {
		return fmt.Errorf("version must be followed by a space")
	}
	return nil
}

func (r *RFC5424) parseTimestamp() error {

	timestamp := []byte{}

	if r.buf[r.position] == NIL_VALUE {
		r.Timestamp = time.Now().UTC().Round(0)
		r.position += 2
		return nil
	}

	for r.position < r.len {
		c := r.buf[r.position]
		if c == ' ' {
			break
		}
		timestamp = append(timestamp, c)
		r.position++
	}

	if len(timestamp) == 0 {
		return fmt.Errorf("timestamp is empty")
	}

	if r.position == r.len {
		return fmt.Errorf("EOL after timestamp")
	}

	date, err := time.Parse(VALID_TIMESTAMP, string(timestamp))

	if err != nil {
		return fmt.Errorf("timestamp is not valid")
	}

	r.Timestamp = date

	r.position++

	if r.position >= r.len {
		return fmt.Errorf("EOL after timestamp")
	}

	return nil
}

func (r *RFC5424) parseHostname() error {
	if r.buf[r.position] == NIL_VALUE {
		r.Hostname = ""
		r.position += 2
		return nil
	}

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
			return fmt.Errorf("hostname is not valid")
		}
	}
	if len(hostname) == 0 {
		return fmt.Errorf("hostname is empty")
	}
	r.Hostname = string(hostname)
	return nil
}

func (r *RFC5424) parseAppName() error {
	if r.buf[r.position] == NIL_VALUE {
		r.Tag = ""
		r.position += 2
		return nil
	}

	appname := []byte{}
	for r.position < r.len {
		c := r.buf[r.position]
		if c == ' ' {
			r.position++
			break
		}
		appname = append(appname, c)
		r.position++
	}

	if len(appname) == 0 {
		return fmt.Errorf("appname is empty")
	}

	if len(appname) > 48 {
		return fmt.Errorf("appname is too long")
	}

	r.Tag = string(appname)
	return nil
}

func (r *RFC5424) parseProcID() error {
	if r.buf[r.position] == NIL_VALUE {
		r.PID = ""
		r.position += 2
		return nil
	}

	procid := []byte{}
	for r.position < r.len {
		c := r.buf[r.position]
		if c == ' ' {
			r.position++
			break
		}
		procid = append(procid, c)
		r.position++
	}

	if len(procid) == 0 {
		return fmt.Errorf("procid is empty")
	}

	if len(procid) > 128 {
		return fmt.Errorf("procid is too long")
	}

	r.PID = string(procid)
	return nil
}

func (r *RFC5424) parseMsgID() error {
	if r.buf[r.position] == NIL_VALUE {
		r.MsgID = ""
		r.position += 2
		return nil
	}

	msgid := []byte{}
	for r.position < r.len {
		c := r.buf[r.position]
		if c == ' ' {
			r.position++
			break
		}
		msgid = append(msgid, c)
		r.position++
	}

	if len(msgid) == 0 {
		return fmt.Errorf("msgid is empty")
	}

	if len(msgid) > 32 {
		return fmt.Errorf("msgid is too long")
	}

	r.MsgID = string(msgid)
	return nil
}

func (r *RFC5424) parseStructuredData() error {
	done := false
	if r.buf[r.position] == NIL_VALUE {
		r.position += 2
		return nil
	}
	if r.buf[r.position] != '[' {
		return fmt.Errorf("structured data must start with '[' or be '-'")
	}
	prev := byte(0)
	for r.position < r.len {
		done = false
		c := r.buf[r.position]
		if c == ']' && prev != '\\' {
			done = true
			r.position++
			if r.position < r.len && r.buf[r.position] == ' ' {
				break
			}
		}
		prev = c
		r.position++
	}
	r.position++
	if !done {
		return fmt.Errorf("structured data must end with ']'")
	}
	return nil
}

func (r *RFC5424) parseMessage() error {
	if r.position == r.len {
		return fmt.Errorf("message is empty")
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

func (r *RFC5424) Parse(message []byte) error {
	r.len = len(message)
	if r.len == 0 {
		return fmt.Errorf("syslog line is empty")
	}
	r.buf = message

	err := r.parsePRI()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after PRI")
	}

	err = r.parseVersion()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after Version")
	}

	err = r.parseTimestamp()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after Timestamp")
	}

	err = r.parseHostname()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after hostname")
	}

	err = r.parseAppName()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after appname")
	}

	err = r.parseProcID()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after ProcID")
	}

	err = r.parseMsgID()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after MSGID")
	}

	err = r.parseStructuredData()
	if err != nil {
		return err
	}

	if r.position >= r.len {
		return fmt.Errorf("EOL after SD")
	}

	err = r.parseMessage()
	if err != nil {
		return err
	}

	return nil
}

func NewRFC5424Parser(opts ...RFC5424Option) *RFC5424 {
	r := &RFC5424{}
	for _, opt := range opts {
		opt(r)
	}
	return r
}
