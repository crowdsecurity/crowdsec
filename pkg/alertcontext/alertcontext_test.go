package alertcontext

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
				"test": {"evt.Parsed.source_ip"},
			},
			valueLength: 100,
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		fmt.Printf("Running test '%s'\n", test.name)
		err := NewAlertContext(test.contextToSend, test.valueLength)
		require.ErrorIs(t, err, test.expectedErr)
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
				"source_ip":         {"evt.Parsed.source_ip"},
				"nonexistent_field": {"evt.Parsed.nonexist"},
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
				"source_ip":      {"evt.Parsed.source_ip"},
				"source_machine": {"evt.Parsed.source_machine"},
				"cve":            {"evt.Parsed.cve"},
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
				"source_ip":      {"evt.Parsed.source_ip"},
				"source_machine": {"evt.Parsed.source_machine"},
				"uri":            {"evt.Parsed.uri"},
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
				"source_ip":      {"evt.Parsed.source_ip"},
				"source_machine": {"evt.Parsed.source_machine"},
				"uri":            {"evt.Parsed.uri"},
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
		require.NoError(t, err)

		metas, _ := EventToContext(test.events)
		assert.ElementsMatch(t, test.expectedResult, metas)
	}
}

func TestValidateContextExpr(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		exprs       []string
		expectedErr *string
	}{
		{
			name: "basic config",
			key:  "source_ip",
			exprs: []string{
				"evt.Parsed.source_ip",
			},
			expectedErr: nil,
		},
		{
			name: "basic config with non existent field",
			key:  "source_ip",
			exprs: []string{
				"evt.invalid.source_ip",
			},
			expectedErr: ptr.Of("compilation of 'evt.invalid.source_ip' failed: type types.Event has no field invalid"),
		},
	}
	for _, test := range tests {
		fmt.Printf("Running test '%s'\n", test.name)

		err := ValidateContextExpr(test.key, test.exprs)
		if test.expectedErr == nil {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, *test.expectedErr)
		}
	}
}

func TestAppsecEventToContext(t *testing.T) {
	tests := []struct {
		name           string
		contextToSend  map[string][]string
		match          types.AppsecEvent
		req            *http.Request
		expectedResult models.Meta
		expectedErrLen int
	}{
		{
			name: "basic test on match",
			contextToSend: map[string][]string{
				"id": {"match.id"},
			},
			match: types.AppsecEvent{
				MatchedRules: types.MatchedRules{
					{
						"id": "test",
					},
				},
			},
			req: &http.Request{},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "id",
					Value: "[\"test\"]",
				},
			},
			expectedErrLen: 0,
		},
		{
			name: "basic test on req",
			contextToSend: map[string][]string{
				"ua": {"req.UserAgent()"},
			},
			match: types.AppsecEvent{
				MatchedRules: types.MatchedRules{
					{
						"id": "test",
					},
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"User-Agent": {"test"},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "ua",
					Value: "[\"test\"]",
				},
			},
			expectedErrLen: 0,
		},
		{
			name: "test on req -> []string",
			contextToSend: map[string][]string{
				"foobarxx": {"req.Header.Values('Foobar')"},
			},
			match: types.AppsecEvent{
				MatchedRules: types.MatchedRules{
					{
						"id": "test",
					},
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"User-Agent": {"test"},
					"Foobar":     {"test1", "test2"},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "foobarxx",
					Value: "[\"test1\",\"test2\"]",
				},
			},
			expectedErrLen: 0,
		},
		{
			name: "test on type int",
			contextToSend: map[string][]string{
				"foobarxx": {"len(req.Header.Values('Foobar'))"},
			},
			match: types.AppsecEvent{
				MatchedRules: types.MatchedRules{
					{
						"id": "test",
					},
				},
			},
			req: &http.Request{
				Header: map[string][]string{
					"User-Agent": {"test"},
					"Foobar":     {"test1", "test2"},
				},
			},
			expectedResult: []*models.MetaItems0{
				{
					Key:   "foobarxx",
					Value: "[\"2\"]",
				},
			},
			expectedErrLen: 0,
		},
	}

	for _, test := range tests {
		// reset cache
		alertContext = Context{}
		// compile
		if err := NewAlertContext(test.contextToSend, 100); err != nil {
			t.Fatalf("failed to compile %s: %s", test.name, err)
		}
		// run

		metas, errors := AppsecEventToContext(test.match, test.req)
		assert.Len(t, errors, test.expectedErrLen)
		assert.ElementsMatch(t, test.expectedResult, metas)
	}
}

func TestEvalAlertContextRules(t *testing.T) {
	tests := []struct {
		name           string
		contextToSend  map[string][]string
		event          types.Event
		match          types.MatchedRule
		req            *http.Request
		expectedResult map[string][]string
		expectedErrLen int
	}{
		{
			name: "no appsec match",
			contextToSend: map[string][]string{
				"source_ip": {"evt.Parsed.source_ip"},
				"id":        {"match.id"},
			},
			event: types.Event{
				Parsed: map[string]string{
					"source_ip":      "1.2.3.4",
					"source_machine": "mymachine",
					"uri":            "/test/test/test/../../../../../../../../",
				},
			},
			expectedResult: map[string][]string{
				"source_ip": {"1.2.3.4"},
				"id":        {},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contextDict := make(map[string][]string)

			alertContext = Context{}
			if err := NewAlertContext(test.contextToSend, 100); err != nil {
				t.Fatalf("failed to compile %s: %s", test.name, err)
			}

			errs := EvalAlertContextRules(test.event, &test.match, test.req, contextDict)
			assert.Len(t, errs, test.expectedErrLen)
			assert.Equal(t, test.expectedResult, contextDict)
		})
	}
}
