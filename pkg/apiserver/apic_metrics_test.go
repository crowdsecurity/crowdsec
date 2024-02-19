package apiserver

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

func TestAPICSendMetrics(t *testing.T) {
	tests := []struct {
		name            string
		duration        time.Duration
		expectedCalls   int
		setUp           func(*apic)
		metricsInterval time.Duration
	}{
		{
			name:            "basic",
			duration:        time.Millisecond * 60,
			metricsInterval: time.Millisecond * 10,
			expectedCalls:   5,
			setUp:           func(api *apic) {},
		},
		{
			name:            "with some metrics",
			duration:        time.Millisecond * 60,
			metricsInterval: time.Millisecond * 10,
			expectedCalls:   5,
			setUp: func(api *apic) {
				api.dbClient.Ent.Machine.Delete().ExecX(context.Background())
				api.dbClient.Ent.Machine.Create().
					SetMachineId("1234").
					SetPassword(testPassword.String()).
					SetIpAddress("1.2.3.4").
					SetScenarios("crowdsecurity/test").
					SetLastPush(time.Time{}).
					SetUpdatedAt(time.Time{}).
					ExecX(context.Background())

				api.dbClient.Ent.Bouncer.Delete().ExecX(context.Background())
				api.dbClient.Ent.Bouncer.Create().
					SetIPAddress("1.2.3.6").
					SetName("someBouncer").
					SetAPIKey("foobar").
					SetRevoked(false).
					SetLastPull(time.Time{}).
					ExecX(context.Background())
			},
		},
	}

	httpmock.RegisterResponder("POST", "http://api.crowdsec.net/api/metrics/", httpmock.NewBytesResponder(200, []byte{}))
	httpmock.Activate()

	defer httpmock.Deactivate()

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			url, err := url.ParseRequestURI("http://api.crowdsec.net/")
			require.NoError(t, err)

			apiClient, err := apiclient.NewDefaultClient(
				url,
				"/api",
				fmt.Sprintf("crowdsec/%s", version.String()),
				nil,
			)
			require.NoError(t, err)

			api := getAPIC(t)
			api.pushInterval = time.Millisecond
			api.pushIntervalFirst = time.Millisecond
			api.apiClient = apiClient
			api.metricsInterval = tc.metricsInterval
			api.metricsIntervalFirst = tc.metricsInterval
			tc.setUp(api)

			stop := make(chan bool)
			httpmock.ZeroCallCounters()
			go api.SendMetrics(stop)
			time.Sleep(tc.duration)
			stop <- true

			info := httpmock.GetCallCountInfo()
			noResponderCalls := info["NO_RESPONDER"]
			responderCalls := info["POST http://api.crowdsec.net/api/metrics/"]
			assert.LessOrEqual(t, absDiff(tc.expectedCalls, responderCalls), 2)
			assert.Zero(t, noResponderCalls)
		})
	}
}
