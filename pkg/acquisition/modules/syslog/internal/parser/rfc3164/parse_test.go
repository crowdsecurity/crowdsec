package rfc3164

import (
	"testing"
	"time"
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
		t.Run(test.input, func(t *testing.T) {
			r := &RFC3164{}
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parsePRI()
			if err != nil {
				if test.expectedErr != "" {
					if err.Error() != test.expectedErr {
						t.Errorf("expected error %s, got %s", test.expectedErr, err.Error())
					}
				} else {
					t.Errorf("unexpected error: %s", err.Error())
				}
			} else {
				if test.expectedErr != "" {
					t.Errorf("expected error %s, got no error", test.expectedErr)
				} else {
					if r.PRI != test.expected {
						t.Errorf("expected %d, got %d", test.expected, r.PRI)
					}
				}
			}
		})
	}
}

func TestTimestamp(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectedErr string
		currentYear bool
	}{
		{"May 20 09:33:54", "0000-05-20T09:33:54Z", "", false},
		{"May 20 09:33:54", "2022-05-20T09:33:54Z", "", true},
		{"May 20 09:33:54 2022", "2022-05-20T09:33:54Z", "", false},
		{"May 1 09:33:54 2022", "2022-05-01T09:33:54Z", "", false},
		{"May 01 09:33:54 2021", "2021-05-01T09:33:54Z", "", true},
		{"foobar", "", "timestamp is not valid", false},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			opts := []RFC3164Option{}
			if test.currentYear {
				opts = append(opts, WithCurrentYear())
			}
			r := NewRFC3164Parser(opts...)
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parseTimestamp()
			if err != nil {
				if test.expectedErr != "" {
					if err.Error() != test.expectedErr {
						t.Errorf("expected error %s, got %s", test.expectedErr, err.Error())
					}
				} else {
					t.Errorf("unexpected error: %s", err.Error())
				}
			} else {
				if test.expectedErr != "" {
					t.Errorf("expected error %s, got no error", test.expectedErr)
				} else {
					if r.Timestamp.Format(time.RFC3339) != test.expected {
						t.Errorf("expected %s, got %s", test.expected, r.Timestamp.Format(time.RFC3339))
					}
				}
			}
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
		{"foo.-bar", "", "hostname is not valid", true},
		{"foo-.bar", "", "hostname is not valid", true},
		{"foo123.bar", "foo123.bar", "", true},
		{"a..", "", "hostname is not valid", true},
		{"foo.bar", "foo.bar", "", false},
		{"foo,bar", "foo,bar", "", false},
		{"foo,bar", "", "hostname is not valid", true},
		{"", "", "hostname is empty", false},
		{".", ".", "", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "hostname is not valid", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bla", "", "hostname is not valid", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bla", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bla", "", false},
		{"a.foo-", "", "hostname is not valid", true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			opts := []RFC3164Option{}
			if test.strictHostname {
				opts = append(opts, WithStrictHostname())
			}
			r := NewRFC3164Parser(opts...)
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parseHostname()
			if err != nil {
				if test.expectedErr != "" {
					if err.Error() != test.expectedErr {
						t.Errorf("expected error %s, got %s", test.expectedErr, err.Error())
					}
				} else {
					t.Errorf("unexpected error: %s", err.Error())
				}
			} else {
				if test.expectedErr != "" {
					t.Errorf("expected error %s, got no error", test.expectedErr)
				} else {
					if r.Hostname != test.expected {
						t.Errorf("expected %s, got %s", test.expected, r.Hostname)
					}
				}
			}
		})
	}
}

func TestTag(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectedPID string
		expectedErr string
	}{
		{"foobar", "foobar", "", ""},
		{"foobar[42]", "foobar", "42", ""},
		{"", "", "", "tag is empty"},
		{"foobar[", "", "", "pid inside tag must be closed with ']'"},
		{"foobar[42", "", "", "pid inside tag must be closed with ']'"},
		{"foobar[asd]", "foobar", "", "pid inside tag must be a number"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			r := &RFC3164{}
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parseTag()
			if err != nil {
				if test.expectedErr != "" {
					if err.Error() != test.expectedErr {
						t.Errorf("expected error %s, got %s", test.expectedErr, err.Error())
					}
				} else {
					t.Errorf("unexpected error: %s", err.Error())
				}
			} else {
				if test.expectedErr != "" {
					t.Errorf("expected error %s, got no error", test.expectedErr)
				} else {
					if r.Tag != test.expected {
						t.Errorf("expected %s, got %s", test.expected, r.Tag)
					}
					if r.PID != test.expectedPID {
						t.Errorf("expected %s, got %s", test.expected, r.Message)
					}
				}
			}
		})
	}
}

func TestMessage(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectedErr string
	}{
		{"foobar: pouet", "pouet", ""},
		{"foobar[42]: test", "test", ""},
		{"foobar[123]: this is a test", "this is a test", ""},
		{"foobar[123]: ", "", "message is empty"},
		{"foobar[123]:", "", "message is empty"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			r := &RFC3164{}
			r.buf = []byte(test.input)
			r.len = len(r.buf)
			err := r.parseMessage()
			if err != nil {
				if test.expectedErr != "" {
					if err.Error() != test.expectedErr {
						t.Errorf("expected error %s, got %s", test.expectedErr, err.Error())
					}
				} else {
					t.Errorf("unexpected error: %s", err.Error())
				}
			} else {
				if test.expectedErr != "" {
					t.Errorf("expected error %s, got no error", test.expectedErr)
				} else {
					if r.Message != test.expected {
						t.Errorf("expected message %s, got %s", test.expected, r.Tag)
					}
				}
			}
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
	}
	tests := []struct {
		input       string
		expected    expected
		expectedErr string
		opts        []RFC3164Option
	}{
		{
			"<12>May 20 09:33:54 UDMPRO,a2edd0c6ae48,udm-1.10.0.3686 kernel: foo", expected{
				Timestamp: time.Date(0, time.May, 20, 9, 33, 54, 0, time.UTC),
				Hostname:  "UDMPRO,a2edd0c6ae48,udm-1.10.0.3686",
				Tag:       "kernel",
				PID:       "",
				Message:   "foo",
				PRI:       12,
			}, "", []RFC3164Option{},
		},
		{
			"<12>May 20 09:33:54 UDMPRO,a2edd0c6ae48,udm-1.10.0.3686 kernel: foo", expected{
				Timestamp: time.Date(2022, time.May, 20, 9, 33, 54, 0, time.UTC),
				Hostname:  "UDMPRO,a2edd0c6ae48,udm-1.10.0.3686",
				Tag:       "kernel",
				PID:       "",
				Message:   "foo",
				PRI:       12,
			}, "", []RFC3164Option{WithCurrentYear()},
		},
		{
			"<12>May 20 09:33:54 UDMPRO,a2edd0c6ae48,udm-1.10.0.3686 kernel: foo", expected{}, "hostname is not valid", []RFC3164Option{WithStrictHostname()},
		},
		{
			"foobar", expected{}, "PRI must start with '<'", []RFC3164Option{},
		},
		{
			"<12>", expected{}, "timestamp is not valid", []RFC3164Option{},
		},
		{
			"<12 May 02 09:33:54 foo.bar", expected{}, "PRI must be a number", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54", expected{}, "hostname is empty", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar", expected{}, "tag is empty", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla[42", expected{}, "pid inside tag must be closed with ']'", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla[42]", expected{}, "message is empty", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla[42]:   ", expected{}, "message is empty", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla", expected{}, "message is empty", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla:", expected{}, "message is empty", []RFC3164Option{},
		},
		{
			"", expected{}, "message is empty", []RFC3164Option{},
		},
		{
			`<13>1 2021-05-18T11:58:40.828081+02:00 mantis sshd 49340 - [timeQuality isSynced="0" tzKnown="1"] blabla`, expected{}, "timestamp is not valid", []RFC3164Option{},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			r := NewRFC3164Parser(test.opts...)
			err := r.Parse([]byte(test.input))
			if err != nil {
				if test.expectedErr != "" {
					if err.Error() != test.expectedErr {
						t.Errorf("expected error '%s', got '%s'", test.expectedErr, err.Error())
					}
				} else {
					t.Errorf("unexpected error: '%s'", err.Error())
				}
			} else {
				if test.expectedErr != "" {
					t.Errorf("expected error '%s', got no error", test.expectedErr)
				} else {
					if r.Timestamp != test.expected.Timestamp {
						t.Errorf("expected timestamp '%s', got '%s'", test.expected.Timestamp, r.Timestamp)
					}
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
				}
			}
		})
	}
}
