package csnet

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

type test struct {
	input   string
	want    Range
	wantErr string
}

func TestAdd2Int(t *testing.T) {
	tests := []test{
		{
			input: "7FFF:FFFF:FFFF:FFFF:aaaa:aaaa:aaaa:fff7",
			want: Range{
				IntIP{16, -math.MaxInt64 + 0x7FFFFFFFFFFFFFFF, -math.MaxInt64 + 0xaaaaaaaaaaaafff7},
				IntIP{16, -math.MaxInt64 + 0x7FFFFFFFFFFFFFFF, -math.MaxInt64 + 0xaaaaaaaaaaaafff7},
			},
		},
		{
			input: "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:fff7",
			want: Range{
				IntIP{16, -math.MaxInt64 + 0xaaaaaaaaaaaaaaaa, -math.MaxInt64 + 0xaaaaaaaaaaaafff7},
				IntIP{16, -math.MaxInt64 + 0xaaaaaaaaaaaaaaaa, -math.MaxInt64 + 0xaaaaaaaaaaaafff7},
			},
		},
		{
			input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff7",
			/*ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff*/

			want: Range{
				IntIP{16, math.MaxInt64, -math.MaxInt64 + 0xfffffffffffffff7},
				IntIP{16, math.MaxInt64, -math.MaxInt64 + 0xfffffffffffffff7},
			},
		},
		{
			input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			/*ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff*/

			want: Range{
				IntIP{16, math.MaxInt64, math.MaxInt64},
				IntIP{16, math.MaxInt64, math.MaxInt64},
			},
		},
		{
			input: "::",
			/*::*/
			want: Range{
				IntIP{16, -math.MaxInt64, -math.MaxInt64},
				IntIP{16, -math.MaxInt64, -math.MaxInt64},
			},
		},
		{
			input: "2001:db8::",
			/*2001:db8:: -> 2001:db8::*/
			want: Range{
				IntIP{16, -math.MaxInt64 + 0x20010DB800000000, -math.MaxInt64},
				IntIP{16, -math.MaxInt64 + 0x20010DB800000000, -math.MaxInt64},
			},
		},
		{
			input: "2001:db8:0000:0000:0000:0000:0000:00ff",
			/*2001:db8:0000:0000:0000:0000:0000:00ff*/
			want: Range{
				IntIP{16, -math.MaxInt64 + 0x20010DB800000000, -math.MaxInt64 + 0xFF},
				IntIP{16, -math.MaxInt64 + 0x20010DB800000000, -math.MaxInt64 + 0xFF},
			},
		},
		{
			input: "1.2.3.4",
			/*1.2.3.4*/
			want: Range{
				IntIP{4, -math.MaxInt64 + 0x01020304, 0},
				IntIP{4, -math.MaxInt64 + 0x01020304, 0},
			},
		},
		{
			input: "::/0",
			/*:: -> ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff*/

			want: Range{
				IntIP{16, -math.MaxInt64, -math.MaxInt64},
				IntIP{16, math.MaxInt64, math.MaxInt64},
			},
		},
		{
			input: "::/64",
			/*:: -> 0000:0000:0000:0000:ffff:ffff:ffff:ffff*/
			want: Range{
				IntIP{16, -math.MaxInt64, -math.MaxInt64},
				IntIP{16, -math.MaxInt64, math.MaxInt64},
			},
		},
		{
			input: "2001:db8::/109",
			/*2001:db8:: -> 2001:db8:0000:0000:0000:0000:0007:ffff*/
			want: Range{
				IntIP{16, -math.MaxInt64 + 0x20010DB800000000, -math.MaxInt64},
				IntIP{16, -math.MaxInt64 + 0x20010DB800000000, -math.MaxInt64 + 0x7FFFF},
			},
		},
		{
			input: "0.0.0.0/0",
			/*0.0.0.0 -> 255.255.255.255*/
			want: Range{
				IntIP{4, -math.MaxInt64, 0},
				IntIP{4, -math.MaxInt64 + 0xFFFFFFFF, 0},
			},
		},
		{
			input: "0.0.0.0/16",
			/*0.0.0.0 -> 0.0.255.255*/
			want: Range{
				IntIP{4, -math.MaxInt64, 0},
				IntIP{4, -math.MaxInt64 + 0x0000FFFF, 0},
			},
		},
		{
			input: "255.255.0.0/16",
			/*255.255.0.0 -> 255.255.255.255*/
			want: Range{
				IntIP{4, -math.MaxInt64 + 0xFFFF0000, 0},
				IntIP{4, -math.MaxInt64 + 0xFFFFFFFF, 0},
			},
		},
		{
			input: "1.2.3.0/24",
			/*1.2.3.0 -> 1.2.3.255*/
			want: Range{
				IntIP{4, -math.MaxInt64 + 0x01020300, 0},
				IntIP{4, -math.MaxInt64 + 0x010203FF, 0},
			},
		},
		{
			input:   "xxx/24",
			wantErr: `netip.ParsePrefix("xxx/24"): ParseAddr("xxx"): unable to parse IP`,
		},
		{
			input:   "xxx2",
			wantErr: `ParseAddr("xxx2"): unable to parse IP`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NewRange(tc.input)
			cstest.RequireErrorContains(t, err, tc.wantErr)

			if tc.wantErr != "" {
				return
			}

			assert.Equal(t, tc.want, got)
		})
	}
}
