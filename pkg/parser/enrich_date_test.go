package parser

import (
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestDateParse(t *testing.T) {
	tests := []struct {
		name             string
		evt              types.Event
		expected_err     *error
		expected_strTime *string
	}{
		{
			name: "RFC3339",
			evt: types.Event{
				StrTime: "2019-10-12T07:20:50.52Z",
			},
			expected_err:     nil,
			expected_strTime: ptr.Of("2019-10-12T07:20:50.52Z"),
		},
		{
			name: "02/Jan/2006:15:04:05 -0700",
			evt: types.Event{
				StrTime: "02/Jan/2006:15:04:05 -0700",
			},
			expected_err:     nil,
			expected_strTime: ptr.Of("2006-01-02T15:04:05-07:00"),
		},
		{
			name: "Dec 17 08:17:43",
			evt: types.Event{
				StrTime:       "2011 X 17 zz 08X17X43 oneone Dec",
				StrTimeFormat: "2006 X 2 zz 15X04X05 oneone Jan",
			},
			expected_err:     nil,
			expected_strTime: ptr.Of("2011-12-17T08:17:43Z"),
		},
	}

	logger := log.WithFields(log.Fields{
		"test": "test",
	})
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			strTime, err := ParseDate(tt.evt.StrTime, &tt.evt, nil, logger)
			if tt.expected_err != nil {
				if err != *tt.expected_err {
					t.Errorf("%s: expected error %v, got %v", tt.name, tt.expected_err, err)
				}
			} else if err != nil {
				t.Errorf("%s: expected no error, got %v", tt.name, err)
			}
			if err != nil {
				return
			}
			if tt.expected_strTime != nil && strTime["MarshaledTime"] != *tt.expected_strTime {
				t.Errorf("expected strTime %s, got %s", *tt.expected_strTime, strTime["MarshaledTime"])
			}
		})
	}
}
