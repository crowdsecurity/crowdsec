package alertcontext

import (
	"fmt"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewAlertContext(t *testing.T) {
	tests := []struct {
		name          string
		contextToSend map[string][]string
		valueLength   int
		expectedErr   error
	}{
		{
			name: "basic config test",
			contextToSend: map[string][]string{
				"test": []string{"evt.Parsed.source_ip"},
			},
			valueLength: 100,
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		fmt.Printf("Running test '%s'\n", test.name)
		err := NewAlertContext(test.contextToSend, test.valueLength)
		assert.ErrorIs(t, err, test.expectedErr)

	}
}

func TestEventToContext(t *testing.T) {
	tests := []struct {
		name           string
		contextToSend  map[string][]string
		valueLength    int
		events         []types.Event
		expectedResult models.Meta
	}{
		{
			name: "basic test",
			contextToSend: map[string][]string{
				"source_ip":         []string{"evt.Parsed.source_ip"},
				"nonexistent_field": []string{"evt.Parsed.nonexist"},
			},
			valueLength: 100,
			events: []types.Event{
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
					},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "source_ip",
					Value: "[\"1.2.3.4\"]",
				},
			},
		},
		{
			name: "test many events",
			contextToSend: map[string][]string{
				"source_ip":      []string{"evt.Parsed.source_ip"},
				"source_machine": []string{"evt.Parsed.source_machine"},
				"cve":            []string{"evt.Parsed.cve"},
			},
			valueLength: 100,
			events: []types.Event{
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"cve":            "CVE-2022-1234",
					},
				},
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"cve":            "CVE-2022-1235",
					},
				},
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"cve":            "CVE-2022-125",
					},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "source_ip",
					Value: "[\"1.2.3.4\"]",
				},
				{
					Key:   "source_machine",
					Value: "[\"mymachine\"]",
				},
				{
					Key:   "cve",
					Value: "[\"CVE-2022-1234\",\"CVE-2022-1235\",\"CVE-2022-125\"]",
				},
			},
		},
		{
			name: "test many events with result above max length (need truncate, keep only 2 on 3 elements)",
			contextToSend: map[string][]string{
				"source_ip":      []string{"evt.Parsed.source_ip"},
				"source_machine": []string{"evt.Parsed.source_machine"},
				"uri":            []string{"evt.Parsed.uri"},
			},
			valueLength: 100,
			events: []types.Event{
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"uri":            "/test/test/test/../../../../../../../../",
					},
				},
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"uri":            "/admin/admin/admin/../../../../../../../../",
					},
				},
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"uri":            "/login/login/login/../../../../../../../../../../../",
					},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "source_ip",
					Value: "[\"1.2.3.4\"]",
				},
				{
					Key:   "source_machine",
					Value: "[\"mymachine\"]",
				},
				{
					Key:   "uri",
					Value: "[\"/test/test/test/../../../../../../../../\",\"/admin/admin/admin/../../../../../../../../\"]",
				},
			},
		},
		{
			name: "test one events with result above max length (need truncate on one element)",
			contextToSend: map[string][]string{
				"source_ip":      []string{"evt.Parsed.source_ip"},
				"source_machine": []string{"evt.Parsed.source_machine"},
				"uri":            []string{"evt.Parsed.uri"},
			},
			valueLength: 100,
			events: []types.Event{
				{
					Parsed: map[string]string{
						"source_ip":      "1.2.3.4",
						"source_machine": "mymachine",
						"uri":            "/test/test/test/../../../../.should_truncate_just_after_this/../../../..../../../../../../../../../../../../../../../end",
					},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "source_machine",
					Value: "[\"mymachine\"]",
				},
				{
					Key:   "uri",
					Value: "[\"/test/test/test/../../../../.should_truncate_just_after_this...\"]",
				},
				{
					Key:   "source_ip",
					Value: "[\"1.2.3.4\"]",
				},
			},
		},
	}

	for _, test := range tests {
		fmt.Printf("Running test '%s'\n", test.name)
		err := NewAlertContext(test.contextToSend, test.valueLength)
		assert.ErrorIs(t, err, nil)

		metas := EventToContext(test.events)
		assert.ElementsMatch(t, test.expectedResult, metas)
	}
}
