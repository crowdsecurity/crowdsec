package cwversion

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStripTags(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no tag, valid version v1.2.3",
			input: "v1.2.3",
			want:  "v1.2.3",
		},
		{
			name:  "tag appended with dash",
			input: "v1.2.3-rc1",
			want:  "v1.2.3",
		},
		{
			name:  "tag appended with tilde",
			input: "v1.2.3~foo3",
			want:  "v1.2.3",
		},
		{
			name:  "tag appended with dot",
			input: "v1.2.3.r1",
			want:  "v1.2.3",
		},
		{
			name:  "tag appended directly",
			input: "v1.2.3r1",
			want:  "v1.2.3",
		},
		{
			name:  "multiple digits in version",
			input: "v10.20.30-rc2",
			want:  "v10.20.30",
		},
		{
			name:  "invalid version (no 'v' prefix)",
			input: "1.2.3-tag",
			want:  "1.2.3-tag",
		},
		{
			name:  "random string",
			input: "some-random-string",
			want:  "some-random-string",
		},
		{
			name:  "freebsd pre-release",
			input: "v1.6.5.r1",
			want:  "v1.6.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripTags(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}
