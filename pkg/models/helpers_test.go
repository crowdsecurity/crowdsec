package models

import (
	"testing"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/stretchr/testify/assert"
)

func TestIsAppsecAlert(t *testing.T) {
	tests := []struct {
		name     string
		alert    *Alert
		expected bool
	}{
		{
			name:     "nil message",
			alert:    &Alert{Message: nil},
			expected: false,
		},
		{
			name:     "empty message",
			alert:    &Alert{Message: ptr.Of("")},
			expected: false,
		},
		{
			name:     "WAF block message",
			alert:    &Alert{Message: ptr.Of("WAF block: crowdsecurity/vpatch-CVE-2023-1234 from 1.2.3.4")},
			expected: true,
		},
		{
			name:     "WAF out-of-band match message",
			alert:    &Alert{Message: ptr.Of("WAF out-of-band match: my-custom-rule from 5.6.7.8")},
			expected: true,
		},
		{
			name:     "regular alert - ssh bruteforce",
			alert:    &Alert{Message: ptr.Of("Ip 1.2.3.4 performed crowdsecurity/ssh-bf")},
			expected: false,
		},
		{
			name:     "regular alert - http probing",
			alert:    &Alert{Message: ptr.Of("Ip 1.2.3.4 performed crowdsecurity/http-probing")},
			expected: false,
		},
		{
			name:     "message contains WAF but not prefix",
			alert:    &Alert{Message: ptr.Of("Some alert about WAF block: not at start")},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.alert.IsAppsecAlert()
			assert.Equal(t, tc.expected, result)
		})
	}
}
