package parser

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestDateParse(t *testing.T) {
	tests := []struct {
		name        string
		evt         types.Event
		expectedErr string
		expected    string
	}{
		{
			name: "RFC3339",
			evt: types.Event{
				StrTime: "2019-10-12T07:20:50.52Z",
			},
			expected: "2019-10-12T07:20:50.52Z",
		},
		{
			name: "02/Jan/2006:15:04:05 -0700",
			evt: types.Event{
				StrTime: "02/Jan/2006:15:04:05 -0700",
			},
			expected: "2006-01-02T15:04:05-07:00",
		},
		{
			name: "Dec 17 08:17:43",
			evt: types.Event{
				StrTime:       "2011 X 17 zz 08X17X43 oneone Dec",
				StrTimeFormat: "2006 X 2 zz 15X04X05 oneone Jan",
			},
			expected: "2011-12-17T08:17:43Z",
		},
		{
			name: "ISO 8601, no timezone",
			evt: types.Event{
				StrTime:       "2024-11-26T20:13:32",
				StrTimeFormat: "",
			},
			expected: "2024-11-26T20:13:32Z",
		},
		{
			name: "ISO 8601, no timezone, milliseconds",
			evt: types.Event{
				StrTime:       "2024-11-26T20:13:32.123",
				StrTimeFormat: "",
			},
			expected: "2024-11-26T20:13:32.123Z",
		},
		{
			name: "ISO 8601, no timezone, microseconds",
			evt: types.Event{
				StrTime:       "2024-11-26T20:13:32.123456",
				StrTimeFormat: "",
			},
			expected: "2024-11-26T20:13:32.123456Z",
		},
		{
			name: "ISO 8601, no timezone, nanoseconds",
			evt: types.Event{
				StrTime:       "2024-11-26T20:13:32.123456789",
				StrTimeFormat: "",
			},
			expected: "2024-11-26T20:13:32.123456789Z",
		},
	}

	logger := log.WithField("test", "test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strTime, err := ParseDate(tt.evt.StrTime, &tt.evt, logger)
			cstest.RequireErrorContains(t, err, tt.expectedErr)
			if tt.expectedErr != "" {
				return
			}
			assert.Equal(t, tt.expected, strTime["MarshaledTime"])
		})
	}
}
