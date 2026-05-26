package appsec

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func testChallengeRequest() *ParsedRequest {
	return &ParsedRequest{
		ClientIP:             "1.2.3.4",
		Host:                 "example.com",
		URI:                  "/protected",
		Method:               "GET",
		UUID:                 "test-uuid",
		RemoteAddrNormalized: "10.0.0.1",
		IsInBand:             true,
		HTTPRequest:          &http.Request{Header: http.Header{"User-Agent": []string{"test-agent"}}},
	}
}

func TestChallengeEventFromRequest(t *testing.T) {
	labels := map[string]string{"type": "appsec"}

	tests := []struct {
		name   string
		info   ChallengeEventInfo
		assert func(t *testing.T, evt pipeline.Event)
	}{
		{
			name: "requested carries the distinct source and reason",
			info: ChallengeEventInfo{Reason: ChallengeReasonRequested, Difficulty: 4},
			assert: func(t *testing.T, evt pipeline.Event) {
				require.Equal(t, pipeline.LOG, evt.Type)
				require.Equal(t, SourceChallenge, evt.Parsed["source"])
				require.Equal(t, string(ChallengeReasonRequested), evt.Parsed["challenge_event"])
				require.Equal(t, "4", evt.Parsed["challenge_difficulty"])
				// client/request metadata
				require.Equal(t, "1.2.3.4", evt.Parsed["source_ip"])
				require.Equal(t, "example.com", evt.Parsed["target_host"])
				require.Equal(t, "test-uuid", evt.Parsed["req_uuid"])
				require.Equal(t, "10.0.0.1", evt.Parsed["remediation_cmpt_ip"])
				require.Equal(t, "test-agent", evt.Parsed["user_agent"])
				require.Equal(t, ModuleName, evt.Line.Module)
				// no fingerprint → no fingerprint fields
				require.NotContains(t, evt.Parsed, "fsid")
			},
		},
		{
			name: "submitted has no fingerprint and no fail reason",
			info: ChallengeEventInfo{Reason: ChallengeReasonSubmitted},
			assert: func(t *testing.T, evt pipeline.Event) {
				require.Equal(t, string(ChallengeReasonSubmitted), evt.Parsed["challenge_event"])
				require.NotContains(t, evt.Parsed, "challenge_fail_reason")
			},
		},
		{
			name: "failed surfaces the fail reason",
			info: ChallengeEventInfo{Reason: ChallengeReasonFailed, FailReason: "invalid proof-of-work"},
			assert: func(t *testing.T, evt pipeline.Event) {
				require.Equal(t, string(ChallengeReasonFailed), evt.Parsed["challenge_event"])
				require.Equal(t, "invalid proof-of-work", evt.Parsed["challenge_fail_reason"])
			},
		},
		{
			name: "solved surfaces fingerprint scalars",
			info: ChallengeEventInfo{
				Reason:     ChallengeReasonSolved,
				Difficulty: 5,
				Fingerprint: &challenge.FingerprintData{
					FSID:             "FS1_abc",
					FastBotDetection: challenge.FlexBool(true),
					Allowlisted:      true,
					AllowlistReason:  "googlebot",
				},
			},
			assert: func(t *testing.T, evt pipeline.Event) {
				require.Equal(t, string(ChallengeReasonSolved), evt.Parsed["challenge_event"])
				require.Equal(t, "FS1_abc", evt.Parsed["fsid"])
				require.Equal(t, "true", evt.Parsed["fingerprint_bot"])
				require.Equal(t, "true", evt.Parsed["fingerprint_allowlisted"])
				require.Equal(t, "googlebot", evt.Parsed["fingerprint_allowlist_reason"])
				// the full fingerprint struct must be available for traversal
				fp, ok := evt.Unmarshaled["fingerprint"].(challenge.FingerprintData)
				require.True(t, ok, "fingerprint should be attached to Unmarshaled")
				require.Equal(t, "FS1_abc", fp.FSID)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt := ChallengeEventFromRequest(testChallengeRequest(), labels, "test-uuid", tc.info)
			tc.assert(t, evt)
		})
	}
}

// emitChallengeEvent must be a no-op (and not panic) when no output channel is wired.
func TestEmitChallengeEventNoChannel(t *testing.T) {
	w := &AppsecRuntimeConfig{}
	require.NotPanics(t, func() {
		w.emitChallengeEvent(testChallengeRequest(), ChallengeEventInfo{Reason: ChallengeReasonRequested})
	})
}

// emitChallengeEvent sends the built event on the wired channel.
func TestEmitChallengeEventSendsOnChannel(t *testing.T) {
	out := make(chan pipeline.Event, 1)
	w := &AppsecRuntimeConfig{OutChan: out, Labels: map[string]string{"type": "appsec"}}

	w.emitChallengeEvent(testChallengeRequest(), ChallengeEventInfo{Reason: ChallengeReasonFailed, FailReason: "boom"})

	evt := <-out
	require.Equal(t, SourceChallenge, evt.Parsed["source"])
	require.Equal(t, string(ChallengeReasonFailed), evt.Parsed["challenge_event"])
	require.Equal(t, "boom", evt.Parsed["challenge_fail_reason"])
}
