package types

import (
	"math"
	"strings"
	"testing"
)

func TestAdd2Int(t *testing.T) {
	tests := []struct {
		in_addr       string
		exp_sz        int
		exp_start_ip  int64
		exp_start_sfx int64
		exp_end_ip    int64
		exp_end_sfx   int64
		exp_error     string
	}{
		{
			in_addr: "::/0",
			/*:: -> ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff*/

			exp_sz:        16,
			exp_start_ip:  -math.MaxInt64,
			exp_start_sfx: -math.MaxInt64,
			exp_end_ip:    math.MaxInt64,
			exp_end_sfx:   math.MaxInt64,
		},
		{
			in_addr: "::/64",
			/*:: -> 0000:0000:0000:0000:ffff:ffff:ffff:ffff*/
			exp_sz:        16,
			exp_start_ip:  -math.MaxInt64,
			exp_start_sfx: -math.MaxInt64,
			exp_end_ip:    -math.MaxInt64,
			exp_end_sfx:   math.MaxInt64,
		},
		{
			in_addr: "2001:db8::/109",
			/*2001:db8:: -> 2001:db8:0000:0000:0000:0000:0007:ffff*/
			exp_sz:        16,
			exp_start_ip:  -math.MaxInt64 + 0x20010DB800000000,
			exp_start_sfx: -math.MaxInt64,
			exp_end_ip:    -math.MaxInt64 + 0x20010DB800000000,
			exp_end_sfx:   -math.MaxInt64 + 0x7FFFF,
		},
		{
			in_addr: "0.0.0.0/0",
			/*0.0.0.0 -> 255.255.255.255*/
			exp_sz:        4,
			exp_start_ip:  -math.MaxInt64,
			exp_start_sfx: 0,
			exp_end_ip:    -math.MaxInt64 + 0xFFFFFFFF,
			exp_end_sfx:   0,
		},
		{
			in_addr: "0.0.0.0/16",
			/*0.0.0.0 -> 0.0.255.255*/
			exp_sz:        4,
			exp_start_ip:  -math.MaxInt64,
			exp_start_sfx: 0,
			exp_end_ip:    -math.MaxInt64 + 0x0000FFFF,
			exp_end_sfx:   0,
		},
		{
			in_addr: "255.255.0.0/16",
			/*255.255.0.0 -> 255.255.255.255*/
			exp_sz:        4,
			exp_start_ip:  -math.MaxInt64 + 0xFFFF0000,
			exp_start_sfx: 0,
			exp_end_ip:    -math.MaxInt64 + 0xFFFFFFFF,
			exp_end_sfx:   0,
		},
		{
			in_addr: "1.2.3.0/24",
			/*1.2.3.0 -> 1.2.3.255*/
			exp_sz:        4,
			exp_start_ip:  -math.MaxInt64 + 0x01020300,
			exp_start_sfx: 0,
			exp_end_ip:    -math.MaxInt64 + 0x010203FF,
			exp_end_sfx:   0,
		},
	}

	for idx, test := range tests {
		sz, start_ip, start_sfx, end_ip, end_sfx, err := Addr2Ints(test.in_addr)
		if err != nil && test.exp_error == "" {
			t.Fatalf("%d unexpected error : %s", idx, err)
		}
		if test.exp_error != "" {
			if !strings.Contains(err.Error(), test.exp_error) {
				t.Fatalf("%d unmatched error : %s != %s", idx, err, test.exp_error)
			}
		}
		if sz != test.exp_sz {
			t.Fatalf("%d unexpected size %d != %d", idx, sz, test.exp_sz)
		}
		if start_ip != test.exp_start_ip {
			t.Fatalf("%d unexpected start_ip %d != %d", idx, start_ip, test.exp_start_ip)
		}
		if sz == 16 {
			if start_sfx != test.exp_start_sfx {
				t.Fatalf("%d unexpected start sfx %d != %d", idx, start_sfx, test.exp_start_sfx)
			}
		}
		if end_ip != test.exp_end_ip {
			t.Fatalf("%d unexpected end ip %d != %d", idx, end_ip, test.exp_end_ip)
		}
		if sz == 16 {
			if end_sfx != test.exp_end_sfx {
				t.Fatalf("%d unexpected end sfx %d != %d", idx, end_sfx, test.exp_end_sfx)
			}
		}

	}
}
