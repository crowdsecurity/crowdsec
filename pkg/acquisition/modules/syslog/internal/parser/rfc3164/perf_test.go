package rfc3164

import "testing"

var e error

func BenchmarkParse(b *testing.B) {
	tests := []struct {
		input string
		opts  []RFC3164Option
	}{
		{
			"<12>May 20 09:33:54 UDMPRO,a2edd0c6ae48,udm-1.10.0.3686 kernel: [1670546.400229] IN=eth9 OUT= MAC=24:5a:4c:7b:0a:4c:34:27:92:67:0f:2b:08:00 SRC=79.124.62.34 DST=x.x.x.x LEN=44 TOS=0x00 PREC=0x00 TTL=243 ID=37520 PROTO=TCP SPT=55055 DPT=51443 WINDOW=1024 RES=0x00 SYN URGP=0", []RFC3164Option{},
		},
		{
			"<12>May 20 09:33:54 UDMPRO,a2edd0c6ae48,udm-1.10.0.3686 kernel: foo", []RFC3164Option{WithCurrentYear()},
		},
		{
			"<12>May 20 09:33:54 UDMPRO,a2edd0c6ae48,udm-1.10.0.3686 kernel: foo", []RFC3164Option{WithStrictHostname()},
		},
		{
			"foobar", []RFC3164Option{},
		},
		{
			"<12>", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla[42", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla[42]", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla[42]:   ", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla", []RFC3164Option{},
		},
		{
			"<12>May 02 09:33:54 foo.bar bla:", []RFC3164Option{},
		},
		{
			"", []RFC3164Option{},
		},
	}
	var err error
	for _, test := range tests {
		b.Run(test.input, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				r := NewRFC3164Parser(test.opts...)
				err = r.Parse([]byte(test.input))
			}
		})
	}
	e = err
}
