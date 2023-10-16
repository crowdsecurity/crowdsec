package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestParseIPSources(t *testing.T) {
	tests := []struct {
		name     string
		evt      Event
		expected []net.IP
	}{
		{
			name: "ParseIPSources: Valid Log Sources",
			evt: Event{
				Type: LOG,
				Meta: map[string]string{
					"source_ip": "127.0.0.1",
				},
			},
			expected: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
		},
		{
			name: "ParseIPSources: Valid Overflow Sources",
			evt: Event{
				Type: OVFLW,
				Overflow: RuntimeAlert{
					Sources: map[string]models.Source{
						"127.0.0.1": {},
					},
				},
			},
			expected: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
		},
		{
			name: "ParseIPSources: Invalid Log Sources",
			evt: Event{
				Type: LOG,
				Meta: map[string]string{
					"source_ip": "IAMNOTANIP",
				},
			},
			expected: []net.IP{
				nil,
			},
		},
		{
			name: "ParseIPSources: Invalid Overflow Sources",
			evt: Event{
				Type: OVFLW,
				Overflow: RuntimeAlert{
					Sources: map[string]models.Source{
						"IAMNOTANIP": {},
					},
				},
			},
			expected: []net.IP{
				nil,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ips := tt.evt.ParseIPSources()
			assert.Equal(t, ips, tt.expected)
		})
	}
}
