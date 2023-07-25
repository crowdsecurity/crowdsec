package rfc5424

import (
	"testing"
	"time"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/stretchr/testify/require"
)

func TestPri(t *testing.T) {
	tests := []struct {
		input       string
		expected    int
		expectedErr string
	}{
		{"<0>", 0, ""},
		{"<19>", 19, ""},
		{"<200>", 200, ""},
		{"<4999>", 0, "PRI must be up to 3 characters long"},
		{"<123", 0, "PRI must end with '>'"},
		{"123>", 0, "PRI must start with '<'"},
		{"<abc>", 0, "PRI must be a number"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			r := &RFC5424{}
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parsePRI()
			cstest.RequireErrorMessage(t, err, test.expectedErr)
		})
	}
}

func TestHostname(t *testing.T) {
	tests := []struct {
		input          string
		expected       string
		expectedErr    string
		strictHostname bool
	}{
		{"127.0.0.1", "127.0.0.1", "", false},
		{"::1", "::1", "", false},
		{"-", "", "", false},
		{"foo.-bar", "", "hostname is not valid", true},
		{"foo-.bar", "", "hostname is not valid", true},
		{"foo123.bar", "foo123.bar", "", true},
		{"a..", "", "hostname is not valid", true},
		{"foo.bar", "foo.bar", "", false},
		{"foo,bar", "foo,bar", "", false},
		{"foo,bar", "", "hostname is not valid", true},
		{".", ".", "", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "hostname is not valid", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bla", "", "hostname is not valid", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bla", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bla", "", false},
		{"a.foo-", "", "hostname is not valid", true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			opts := []RFC5424Option{}
			if test.strictHostname {
				opts = append(opts, WithStrictHostname())
			}
			r := NewRFC5424Parser(opts...)
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parseHostname()
			cstest.RequireErrorMessage(t, err, test.expectedErr)
		})
	}
}

func TestParse(t *testing.T) {
	type expected struct {
		Timestamp time.Time
		Hostname  string
		Tag       string
		PID       string
		Message   string
		PRI       int
		MsgID     string
	}

	tests := []struct {
		name        string
		input       string
		expected    expected
		expectedErr string
		opts        []RFC5424Option
	}{
		{
			"valid msg",
			`<13>1 2021-05-18T11:58:40.828081+02:42 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla`, expected{
				Timestamp: time.Date(2021, 5, 18, 11, 58, 40, 828081000, time.FixedZone("+0242", 9720)),
				Hostname:  "mantis",
				Tag:       "sshd",
				PID:       "49340",
				MsgID:     "",
				Message:   "blabla",
				PRI:       13,
			}, "", []RFC5424Option{},
		},
		{
			"valid msg with msgid",
			`<13>1 2021-05-18T11:58:40.828081+02:42 mantis foobar 49340 123123 [timeQuality isSynced="0" tzKnown="1"] blabla`, expected{
				Timestamp: time.Date(2021, 5, 18, 11, 58, 40, 828081000, time.FixedZone("+0242", 9720)),
				Hostname:  "mantis",
				Tag:       "foobar",
				PID:       "49340",
				MsgID:     "123123",
				Message:   "blabla",
				PRI:       13,
			}, "", []RFC5424Option{},
		},
		{
			"valid msg with repeating SD",
			`<13>1 2021-05-18T11:58:40.828081+02:42 mantis foobar 49340 123123 [timeQuality isSynced="0" tzKnown="1"][foo="bar][a] blabla`, expected{
				Timestamp: time.Date(2021, 5, 18, 11, 58, 40, 828081000, time.FixedZone("+0242", 9720)),
				Hostname:  "mantis",
				Tag:       "foobar",
				PID:       "49340",
				MsgID:     "123123",
				Message:   "blabla",
				PRI:       13,
			}, "", []RFC5424Option{},
		},
		{
			"invalid SD",
			`<13>1 2021-05-18T11:58:40.828081+02:00 mantis foobar 49340 123123 [timeQuality asd`, expected{}, "structured data must end with ']'", []RFC5424Option{},
		},
		{
			"invalid version",
			`<13>42 2021-05-18T11:58:40.828081+02:00 mantis foobar 49340 123123 [timeQuality isSynced="0" tzKnown="1"] blabla`, expected{}, "version must be 1", []RFC5424Option{},
		},
		{
			"invalid message",
			`<13>1`, expected{}, "version must be followed by a space", []RFC5424Option{},
		},
		{
			"valid msg with empty fields",
			`<13>1 - foo - - - - blabla`, expected{
				Timestamp: time.Now().UTC(),
				Hostname:  "foo",
				PRI:       13,
				Message:   "blabla",
			}, "", []RFC5424Option{},
		},
		{
			"valid msg with empty fields",
			`<13>1 - - - - - - blabla`, expected{
				Timestamp: time.Now().UTC(),
				PRI:       13,
				Message:   "blabla",
			}, "", []RFC5424Option{},
		},
		{
			"valid msg with escaped SD",
			`<13>1 2022-05-24T10:57:39Z testhostname unknown - sn="msgid" [foo="\]" bar="a\""][a b="[\]" c] testmessage`,
			expected{
				PRI:       13,
				Timestamp: time.Date(2022, 5, 24, 10, 57, 39, 0, time.UTC),
				Tag:       "unknown",
				Hostname:  "testhostname",
				MsgID:     `sn="msgid"`,
				Message:   `testmessage`,
			}, "", []RFC5424Option{},
		},
		{
			"valid complex msg",
			`<13>1 2022-05-24T10:57:39Z myhostname unknown - sn="msgid" [all@0 request="/dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js" src_ip_geo_country="DE" MONTH="May" COMMONAPACHELOG="1.1.1.1 - - [24/May/2022:10:57:37 +0200\] \"GET /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js HTTP/2.0\" 304 0" auth="-" HOUR="10" gl2_remote_ip="172.31.32.142" ident="-" gl2_remote_port="43375" BASE10NUM="[2.0, 304, 0\]" pid="-1" program="nginx" gl2_source_input="623ed3440183476d61cff974" INT="+0200" is_private_ip="false" YEAR="2022" src_ip_geo_city="Achern" clientip="1.1.1.1" USERNAME="-" src_ip_geo_location="48.6306,8.0743" gl2_source_node="8620c2bb-dbb7-4535-b1ce-83df223acd8d" MINUTE="57" timestamp="2022-05-24T08:57:37.000Z" src_ip_asn="3320" level="5" IP="1.1.1.1" IPV4="1.1.1.1" verb="GET" gl2_message_id="01G3TMJFAMFS4H60QSF7M029R0" TIME="10:57:37" USER="-" src_ip_asn_owner="Deutsche Telekom AG" response="304" bytes="0" SECOND="37" httpversion="2.0" _id="906ce155-db3f-11ec-b25f-0a189ba2c64e" facility="user" MONTHDAY="24"] source: sn="www.foobar.com" | message: 1.1.1.1 - - [24/May/2022:10:57:37 +0200] "GET /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js HTTP/2.0" 304 0 "https://www.foobar.com/sw.js" "Mozilla/5.0 (Linux; Android 9; ANE-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36" "-" "www.foobar.com" sn="www.foobar.com" rt=0.000 ua="-" us="-" ut="-" ul="-" cs=HIT { request: /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js | src_ip_geo_country: DE | MONTH: May | COMMONAPACHELOG: 1.1.1.1 - - [24/May/2022:10:57:37 +0200] "GET /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js HTTP/2.0" 304 0 | auth: - | HOUR: 10 | gl2_remote_ip: 172.31.32.142 | ident: - | gl2_remote_port: 43375 | BASE10NUM: [2.0, 304, 0] | pid: -1 | program: nginx | gl2_source_input: 623ed3440183476d61cff974 | INT: +0200 | is_private_ip: false | YEAR: 2022 | src_ip_geo_city: Achern | clientip: 1.1.1.1 | USERNAME:`,
			expected{
				Timestamp: time.Date(2022, 5, 24, 10, 57, 39, 0, time.UTC),
				Hostname:  "myhostname",
				Tag:       "unknown",
				PRI:       13,
				MsgID:     `sn="msgid"`,
				Message:   `source: sn="www.foobar.com" | message: 1.1.1.1 - - [24/May/2022:10:57:37 +0200] "GET /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js HTTP/2.0" 304 0 "https://www.foobar.com/sw.js" "Mozilla/5.0 (Linux; Android 9; ANE-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36" "-" "www.foobar.com" sn="www.foobar.com" rt=0.000 ua="-" us="-" ut="-" ul="-" cs=HIT { request: /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js | src_ip_geo_country: DE | MONTH: May | COMMONAPACHELOG: 1.1.1.1 - - [24/May/2022:10:57:37 +0200] "GET /dist/precache-manifest.58b57debe6bc4f96698da0dc314461e9.js HTTP/2.0" 304 0 | auth: - | HOUR: 10 | gl2_remote_ip: 172.31.32.142 | ident: - | gl2_remote_port: 43375 | BASE10NUM: [2.0, 304, 0] | pid: -1 | program: nginx | gl2_source_input: 623ed3440183476d61cff974 | INT: +0200 | is_private_ip: false | YEAR: 2022 | src_ip_geo_city: Achern | clientip: 1.1.1.1 | USERNAME:`,
			}, "", []RFC5424Option{},
		},
		{
			"partial message",
			`<13>1 2022-05-24T10:57:39Z foo bar -`,
			expected{},
			"EOL after ProcID",
			[]RFC5424Option{},
		},
		{
			"partial message",
			`<13>1 2022-05-24T10:57:39Z foo bar `,
			expected{},
			"EOL after appname",
			[]RFC5424Option{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			r := NewRFC5424Parser(test.opts...)
			err := r.Parse([]byte(test.input))
			cstest.RequireErrorMessage(t, err, test.expectedErr)
			if test.expectedErr != "" {
				return
			}
			require.WithinDuration(t, test.expected.Timestamp, r.Timestamp, time.Second)
			if r.Hostname != test.expected.Hostname {
				t.Errorf("expected hostname '%s', got '%s'", test.expected.Hostname, r.Hostname)
			}
			if r.Tag != test.expected.Tag {
				t.Errorf("expected tag '%s', got '%s'", test.expected.Tag, r.Tag)
			}
			if r.PID != test.expected.PID {
				t.Errorf("expected pid '%s', got '%s'", test.expected.PID, r.PID)
			}
			if r.Message != test.expected.Message {
				t.Errorf("expected message '%s', got '%s'", test.expected.Message, r.Message)
			}
			if r.PRI != test.expected.PRI {
				t.Errorf("expected pri '%d', got '%d'", test.expected.PRI, r.PRI)
			}
			if r.MsgID != test.expected.MsgID {
				t.Errorf("expected msgid '%s', got '%s'", test.expected.MsgID, r.MsgID)
			}
		})
	}
}
