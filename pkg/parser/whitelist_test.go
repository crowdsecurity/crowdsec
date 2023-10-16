package parser

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestWhitelistCompile(t *testing.T) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
	}
	tests := []struct {
		name        string
		whitelist   Whitelist
		expectedErr string
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
			expectedErr: "invalid CIDR address",
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
			expectedErr: "types.Event has no field",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			node.Whitelist = tt.whitelist
			_, err := node.CompileWLs()
			cstest.RequireErrorContains(t, err, tt.expectedErr)
		})
	}
}

func TestWhitelistCheck(t *testing.T) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
	}
	tests := []struct {
		name      string
		whitelist Whitelist
		event     *types.Event
		expected  bool
	}{
		{
			name: "IP Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Ips: []string{
					"127.0.0.1",
				},
			},
			event: &types.Event{
				Meta: map[string]string{
					"source_ip": "127.0.0.1",
				},
			},
			expected: true,
		},
		{
			name: "IP Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Ips: []string{
					"127.0.0.1",
				},
			},
			event: &types.Event{
				Meta: map[string]string{
					"source_ip": "127.0.0.2",
				},
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
			event: &types.Event{
				Meta: map[string]string{
					"source_ip": "127.0.0.1",
				},
			},
			expected: true,
		},
		{
			name: "CIDR Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"127.0.0.1/32",
				},
			},
			event: &types.Event{
				Meta: map[string]string{
					"source_ip": "127.0.0.2",
				},
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
			expected: true,
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
		{
			name: "Postoverflow IP Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Ips: []string{
					"192.168.1.1",
				},
			},
			event: &types.Event{
				Type: types.OVFLW,
				Overflow: types.RuntimeAlert{
					Sources: map[string]models.Source{
						"192.168.1.1": {},
					},
				},
			},
			expected: true,
		},
		{
			name: "Postoverflow IP Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Ips: []string{
					"192.168.1.2",
				},
			},
			event: &types.Event{
				Type: types.OVFLW,
				Overflow: types.RuntimeAlert{
					Sources: map[string]models.Source{
						"192.168.1.1": {},
					},
				},
			},
		},
		{
			name: "Postoverflow CIDR Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"192.168.1.1/32",
				},
			},
			event: &types.Event{
				Type: types.OVFLW,
				Overflow: types.RuntimeAlert{
					Sources: map[string]models.Source{
						"192.168.1.1": {},
					},
				},
			},
			expected: true,
		},
		{
			name: "Postoverflow CIDR Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Cidrs: []string{
					"192.168.1.2/32",
				},
			},
			event: &types.Event{
				Type: types.OVFLW,
				Overflow: types.RuntimeAlert{
					Sources: map[string]models.Source{
						"192.168.1.1": {},
					},
				},
			},
		},
		{
			name: "Postoverflow EXPR Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Exprs: []string{
					"evt.Overflow.APIAlerts[0].Source.Cn == 'test'",
				},
			},
			event: &types.Event{
				Type: types.OVFLW,
				Overflow: types.RuntimeAlert{
					APIAlerts: []models.Alert{
						{
							Source: &models.Source{
								Cn: "test",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Postoverflow EXPR Not Whitelisted",
			whitelist: Whitelist{
				Reason: "test",
				Exprs: []string{
					"evt.Overflow.APIAlerts[0].Source.Cn == 'test2'",
				},
			},
			event: &types.Event{
				Type: types.OVFLW,
				Overflow: types.RuntimeAlert{
					APIAlerts: []models.Alert{
						{
							Source: &models.Source{
								Cn: "test",
							},
						},
					},
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
			isWhitelisted := node.CheckIPsWL(tt.event.ParseIPSources())
			if !isWhitelisted {
				isWhitelisted, err = node.CheckExprWL(map[string]interface{}{"evt": tt.event})
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, isWhitelisted)
		})
	}
}
