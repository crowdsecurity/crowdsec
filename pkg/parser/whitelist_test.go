package parser

import (
	"net"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func TestWhitelistCompile(t *testing.T) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
	}
	tests := []struct {
		name         string
		whitelist    Whitelist
		expected_err bool
	}{
		{
			name: "Valid CIDR whitelist",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"127.0.0.1/24",
				},
			},
		},
		{
			name: "Invalid CIDR whitelist",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"127.0.0.1/1000",
				},
			},
			expected_err: true,
		},
		{
			name: "Valid EXPR whitelist",
			whitelist: Whitelist{
				Reason: "test",
				Exprs: []string{
					"1==1",
				},
			},
		},
		{
			name: "Invalid EXPR whitelist",
			whitelist: Whitelist{
				Reason: "test",
				Exprs: []string{
					"evt.THISPROPERTYSHOULDERROR == true",
				},
			},
			expected_err: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			node.Whitelist = tt.whitelist
			_, err := node.CompileWLs()
			if err == nil && tt.expected_err {
				t.Fatalf("Whitelist expected to error %s", tt.name)
			}
		})
	}
}

func TestWhitelistCheck(t *testing.T) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
	}
	tests := []struct {
		name             string
		whitelist        Whitelist
		sources          []net.IP
		event            *types.Event
		expected_outcome bool
	}{
		{
			name: "IP Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Ips: []string{
					"127.0.0.1",
				},
			},
			sources: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
			expected_outcome: true,
		},
		{
			name: "IP Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Ips: []string{
					"127.0.0.1",
				},
			},
			sources: []net.IP{
				net.ParseIP("127.0.0.2"),
			},
		},
		{
			name: "CIDR Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"127.0.0.1/32",
				},
			},
			sources: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
			expected_outcome: true,
		},
		{
			name: "CIDR Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"127.0.0.1/32",
				},
			},
			sources: []net.IP{
				net.ParseIP("127.0.0.2"),
			},
		},
		{
			name: "EXPR Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Exprs: []string{
					"evt.Meta.source_ip == '127.0.0.1'",
				},
			},
			event: &types.Event{
				Meta: map[string]string{
					"source_ip": "127.0.0.1",
				},
			},
			expected_outcome: true,
		},
		{
			name: "EXPR Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Exprs: []string{
					"evt.Meta.source_ip == '127.0.0.1'",
				},
			},
			event: &types.Event{
				Meta: map[string]string{
					"source_ip": "127.0.0.2",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var err error
			node.Whitelist = tt.whitelist
			node.CompileWLs()
			isWhitelisted := node.CheckIPsWL(tt.sources)
			if !isWhitelisted {
				isWhitelisted, err = node.CheckExprWL(map[string]interface{}{"evt": tt.event})
			}
			if err != nil {
				t.Fatalf("failed to check whitelist: %s", err)
			}
			if isWhitelisted != tt.expected_outcome {
				t.Fatalf("expected %t, got %t", tt.expected_outcome, isWhitelisted)
			}
		})
	}
}
