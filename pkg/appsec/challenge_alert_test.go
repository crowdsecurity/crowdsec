package appsec

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// metaValue returns the first event-Meta value matching key (plain strings).
func metaValue(alert *models.Alert, key string) string {
	for _, evt := range alert.Events {
		for _, item := range evt.Meta {
			if item.Key == key {
				return item.Value
			}
		}
	}
	return ""
}

// contextValues decodes an alert-context (Meta) entry, which is a JSON string
// array, into its values.
func contextValues(t *testing.T, alert *models.Alert, key string) []string {
	t.Helper()
	for _, item := range alert.Meta {
		if item.Key == key {
			var vals []string
			require.NoError(t, json.Unmarshal([]byte(item.Value), &vals))
			return vals
		}
	}
	return nil
}

func rejectedInfo(t *testing.T) ChallengeEventInfo {
	t.Helper()
	return ChallengeEventInfo{
		Reason:       ChallengeReasonRejected,
		FailReason:   "score >= 75: cdp,webdriver",
		Fingerprint:  fpEuropeParisCDP(t),
		Score:        105,
		ScoreReasons: []string{"cdp", "webdriver"},
	}
}

func challengeReq(t *testing.T, inBand bool) *ParsedRequest {
	t.Helper()
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://x/", http.NoBody)
	require.NoError(t, err)
	return &ParsedRequest{
		HTTPRequest:          httpReq,
		ClientIP:             testIPUS,
		RemoteAddrNormalized: "10.0.0.1",
		Host:                 "example.com",
		URI:                  "/protected",
		Method:               http.MethodPost,
		IsInBand:             inBand,
	}
}

func TestBuildChallengeAlertRejected(t *testing.T) {
	setupGeoIP(t)
	w := makeRuntime()

	alert := w.buildChallengeAlert(challengeReq(t, true), rejectedInfo(t))

	require.Equal(t, types.BotDetectionAlertKind.String(), alert.Kind)
	require.NotNil(t, alert.Scenario)
	assert.Equal(t, challengeScenario, *alert.Scenario)

	// The alert must satisfy the swagger contract (all required fields set).
	require.NoError(t, alert.Validate(strfmt.Default))

	// Request details live on the event (plain strings).
	assert.Equal(t, string(ChallengeReasonRejected), metaValue(alert, "challenge_event"))
	// Detection reasoning lives in the alert context (JSON string arrays).
	assert.Equal(t, []string{"rejected"}, contextValues(t, alert, "detection_outcome"))
	assert.Equal(t, []string{"score >= 75: cdp,webdriver"}, contextValues(t, alert, "detection_reason"))
	assert.Equal(t, []string{"105"}, contextValues(t, alert, "request_score"))
	assert.Equal(t, []string{"cdp", "webdriver"}, contextValues(t, alert, "request_score_reasons"))
	assert.Equal(t, []string{"true"}, contextValues(t, alert, "fingerprint_bot"))
	assert.NotEmpty(t, contextValues(t, alert, "bot_signals"))
	assert.Equal(t, "US", alert.Source.Cn)
}

func TestBuildChallengeAlertFailed(t *testing.T) {
	setupGeoIP(t)
	w := makeRuntime()

	info := ChallengeEventInfo{
		Reason:     ChallengeReasonFailed,
		FailReason: "cookie expired",
	}
	alert := w.buildChallengeAlert(challengeReq(t, true), info)

	require.NoError(t, alert.Validate(strfmt.Default))
	assert.Equal(t, challengeScenario, *alert.Scenario)
	assert.Equal(t, "cookie expired", metaValue(alert, "challenge_fail_reason"))       // event meta
	assert.Equal(t, []string{"cookie expired"}, contextValues(t, alert, "detection_reason")) // context
	// No fingerprint on a failed submission → no bot signals.
	assert.Empty(t, contextValues(t, alert, "bot_signals"))
}

func TestEmitChallengeAlertSendsOnChan(t *testing.T) {
	setupGeoIP(t)
	out := make(chan pipeline.Event, 4)
	w := makeRuntime()
	w.OutChan = out

	state := &AppsecRequestState{Response: AppsecTempResponse{SendAlert: true}}
	w.emitChallengeAlert(state, challengeReq(t, true), rejectedInfo(t))

	require.Len(t, out, 1)
	evt := <-out
	assert.Equal(t, pipeline.APPSEC, evt.Type)
	require.NotNil(t, evt.Overflow.Alert)
	assert.Equal(t, types.BotDetectionAlertKind.String(), evt.Overflow.Alert.Kind)
	require.Len(t, evt.Overflow.APIAlerts, 1)
	assert.Contains(t, evt.Overflow.Sources, testIPUS)
}

func TestEmitChallengeAlertCancelSuppresses(t *testing.T) {
	out := make(chan pipeline.Event, 4)
	w := makeRuntime()
	w.OutChan = out

	state := &AppsecRequestState{Response: AppsecTempResponse{SendAlert: false}}
	w.emitChallengeAlert(state, challengeReq(t, true), rejectedInfo(t))

	assert.Empty(t, out, "CancelAlert (SendAlert=false) must suppress the alert")
}

func TestEmitChallengeAlertOutOfBandNoop(t *testing.T) {
	out := make(chan pipeline.Event, 4)
	w := makeRuntime()
	w.OutChan = out

	state := &AppsecRequestState{Response: AppsecTempResponse{SendAlert: true}}
	w.emitChallengeAlert(state, challengeReq(t, false), rejectedInfo(t))

	assert.Empty(t, out, "out-of-band requests must not emit a challenge alert")
}

func TestEmitChallengeAlertNilChanNoop(t *testing.T) {
	w := makeRuntime() // OutChan is nil
	state := &AppsecRequestState{Response: AppsecTempResponse{SendAlert: true}}
	require.NotPanics(t, func() {
		w.emitChallengeAlert(state, challengeReq(t, true), rejectedInfo(t))
	})
}
