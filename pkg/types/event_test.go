package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestSetParsed(t *testing.T) {
	tests := []struct {
		name     string
		evt      *Event
		key      string
		value    string
		expected bool
	}{
		{
			name:     "SetParsed: Valid",
			evt:      &Event{},
			key:      "test",
			value:    "test",
			expected: true,
		},
		{
			name:     "SetParsed: Existing map",
			evt:      &Event{Parsed: map[string]string{}},
			key:      "test",
			value:    "test",
			expected: true,
		},
		{
			name:     "SetParsed: Existing map+key",
			evt:      &Event{Parsed: map[string]string{"test": "foobar"}},
			key:      "test",
			value:    "test",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.evt.SetParsed(tt.key, tt.value)
			assert.Equal(t, tt.value, tt.evt.Parsed[tt.key])
		})
	}
}

func TestSetMeta(t *testing.T) {
	tests := []struct {
		name     string
		evt      *Event
		key      string
		value    string
		expected bool
	}{
		{
			name:     "SetMeta: Valid",
			evt:      &Event{},
			key:      "test",
			value:    "test",
			expected: true,
		},
		{
			name:     "SetMeta: Existing map",
			evt:      &Event{Meta: map[string]string{}},
			key:      "test",
			value:    "test",
			expected: true,
		},
		{
			name:     "SetMeta: Existing map+key",
			evt:      &Event{Meta: map[string]string{"test": "foobar"}},
			key:      "test",
			value:    "test",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.evt.SetMeta(tt.key, tt.value)
			assert.Equal(t, tt.value, tt.evt.GetMeta(tt.key))
		})
	}
}

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
		t.Run(tt.name, func(t *testing.T) {
			ips := tt.evt.ParseIPSources()
			assert.Equal(t, tt.expected, ips)
		})
	}
}
