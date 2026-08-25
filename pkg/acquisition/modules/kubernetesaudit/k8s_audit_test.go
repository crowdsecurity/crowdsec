package kubernetesauditacquisition

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestInvalidConfig(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name: "invalid_port",
			config: `source: k8s-audit
listen_addr: 127.0.0.1
listen_port: 9999999
webhook_path: /k8s-audit`,
			expectedErr: "listen tcp: address 9999999: invalid port",
		},
	}

	subLogger := log.WithField("type", ModuleName)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := make(chan pipeline.Event)
			tb := &tomb.Tomb{}

			f := Source{}

			err := f.UnmarshalConfig([]byte(test.config))

			require.NoError(t, err)

			err = f.Configure(ctx, []byte(test.config), subLogger, metrics.AcquisitionMetricsLevelNone)

			require.NoError(t, err)
			err = f.StreamingAcquisition(ctx, out, tb)
			require.NoError(t, err)

			time.Sleep(1 * time.Second)
			tb.Kill(nil)
			err = tb.Wait()
			cstest.RequireErrorContains(t, err, test.expectedErr)
		})
	}
}

func TestHandler(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name               string
		expectedStatusCode int
		body               string
		method             string
		eventCount         int
	}{
		{
			name: "valid_json",
			method:             "POST",
			expectedStatusCode: 200,
			body: `
{
	"Items": [
	  {
		"Level": "RequestResponse",
		"AuditID": "2fca7950-03b6-41fa-95cd-08c5bcec8487",
		"Stage": "ResponseComplete",
		"RequestURI": "/api/v1/namespaces/default/pods?fieldManager=kubectl-client-side-apply\u0026fieldValidation=Strict",
		"Verb": "create",
		"User": {
		  "username": "minikube-user",
		  "groups": [
			"system:masters",
			"system:authenticated"
		  ]
		},
		"ImpersonatedUser": null,
		"SourceIPs": [
		  "192.168.9.212"
		],
		"UserAgent": "kubectl.exe/v1.25.2 (windows/amd64) kubernetes/5835544",
		"ObjectRef": {
		  "Resource": "pods",
		  "Namespace": "default",
		  "Name": "test-pod-hostpath",
		  "UID": "",
		  "APIGroup": "",
		  "APIVersion": "v1",
		  "ResourceVersion": "",
		  "Subresource": ""
		},
		"ResponseStatus": {
		  "metadata": {},
		  "code": 201
		},
		"RequestObject": {},
		"ResponseObject": {},
		"RequestReceivedTimestamp": "2022-09-26T15:24:52.316938Z",
		"StageTimestamp": "2022-09-26T15:24:52.322575Z",
		"Annotations": {
		  "authorization.k8s.io/decision": "allow",
		  "authorization.k8s.io/reason": "",
		  "pod-security.kubernetes.io/enforce-policy": "privileged:latest"
		}
	  },
	  {
		"Level": "RequestResponse",
		"AuditID": "2fca7950-03b6-41fa-95cd-08c5bcec8487",
		"Stage": "ResponseComplete",
		"RequestURI": "/api/v1/namespaces/default/pods?fieldManager=kubectl-client-side-apply\u0026fieldValidation=Strict",
		"Verb": "create",
		"User": {
		  "username": "minikube-user",
		  "groups": [
			"system:masters",
			"system:authenticated"
		  ]
		},
		"ImpersonatedUser": null,
		"SourceIPs": [
		  "192.168.9.212"
		],
		"UserAgent": "kubectl.exe/v1.25.2 (windows/amd64) kubernetes/5835544",
		"ObjectRef": {
		  "Resource": "pods",
		  "Namespace": "default",
		  "Name": "test-pod-hostpath",
		  "UID": "",
		  "APIGroup": "",
		  "APIVersion": "v1",
		  "ResourceVersion": "",
		  "Subresource": ""
		},
		"ResponseStatus": {
		  "metadata": {},
		  "code": 201
		},
		"RequestObject": {},
		"ResponseObject": {},
		"RequestReceivedTimestamp": "2022-09-26T15:24:52.316938Z",
		"StageTimestamp": "2022-09-26T15:24:52.322575Z",
		"Annotations": {
		  "authorization.k8s.io/decision": "allow",
		  "authorization.k8s.io/reason": "",
		  "pod-security.kubernetes.io/enforce-policy": "privileged:latest"
		}
	  }
	]
  }`,
			eventCount: 2,
		},
		{
			name: "invalid_json",
			expectedStatusCode: 500,
			body:               "invalid json",
			method:             "POST",
			eventCount:         0,
		},
		{
			name: "invalid_method",
			expectedStatusCode: 405,
			method:             "GET",
			eventCount:         0,
		},
	}

	subLogger := log.WithField("type", ModuleName)

	for idx, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := make(chan pipeline.Event)
			tb := &tomb.Tomb{}
			eventCount := 0

			tb.Go(func() error {
				for {
					select {
					case <-out:
						eventCount++
					case <-tb.Dying():
						return nil
					}
				}
			})

			f := Source{}

			port := 49234+idx
			config := fmt.Sprintf(`source: k8s-audit
listen_addr: 127.0.0.1
listen_port: %d
webhook_path: /k8s-audit`, port)

			err := f.UnmarshalConfig([]byte(config))
			require.NoError(t, err)

			err = f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			req := httptest.NewRequest(test.method, "/k8s-audit", strings.NewReader(test.body))
			w := httptest.NewRecorder()

			err = f.StreamingAcquisition(ctx, out, tb)
			require.NoError(t, err)

			f.webhookHandler(w, req)

			res := w.Result()

			assert.Equal(t, test.expectedStatusCode, res.StatusCode)
			// time.Sleep(1 * time.Second)
			require.NoError(t, err)

			tb.Kill(nil)
			err = tb.Wait()
			require.NoError(t, err)

			assert.Equal(t, test.eventCount, eventCount)
		})
	}
}

func TestMaxBodySize(t *testing.T) {
	ctx := t.Context()

	// smallest valid payload, one audit event
	body := `{"Items":[{"Level":"RequestResponse","AuditID":"2fca7950-03b6-41fa-95cd-08c5bcec8487","Stage":"ResponseComplete","StageTimestamp":"2022-09-26T15:24:52.322575Z"}]}`

	tests := []struct {
		name               string
		maxBodySize        string
		knownLength        bool
		expectedStatusCode int
		eventCount         int
	}{
		{
			name:               "default_max_body_size",
			expectedStatusCode: 200,
			knownLength:        true,
			eventCount:         1,
		},
		{
			name:               "under_max_body_size",
			maxBodySize:        "\nmax_body_size: 4096",
			knownLength:        true,
			expectedStatusCode: 200,
			eventCount:         1,
		},
		{
			name:               "over_max_body_size",
			maxBodySize:        "\nmax_body_size: 10",
			knownLength:        true,
			expectedStatusCode: 413,
			eventCount:         0,
		},
		{
			// a body sent without a known length must not bypass max_body_size
			name:               "over_max_body_size_unknown_length",
			maxBodySize:        "\nmax_body_size: 10",
			knownLength:        false,
			expectedStatusCode: 413,
			eventCount:         0,
		},
	}

	subLogger := log.WithField("type", ModuleName)

	for idx, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := make(chan pipeline.Event)
			tb := &tomb.Tomb{}
			eventCount := 0

			tb.Go(func() error {
				for {
					select {
					case <-out:
						eventCount++
					case <-tb.Dying():
						return nil
					}
				}
			})

			f := Source{}

			config := fmt.Sprintf(`source: k8s-audit
listen_addr: 127.0.0.1
listen_port: %d
webhook_path: /k8s-audit%s`, 49334+idx, test.maxBodySize)

			err := f.Configure(ctx, []byte(config), subLogger, metrics.AcquisitionMetricsLevelNone)
			require.NoError(t, err)

			err = f.StreamingAcquisition(ctx, out, tb)
			require.NoError(t, err)

			var reader io.Reader = strings.NewReader(body)
			if !test.knownLength {
				// hide the concrete type so httptest does not set ContentLength
				reader = io.MultiReader(reader)
			}

			req := httptest.NewRequest(http.MethodPost, "/k8s-audit", reader)
			w := httptest.NewRecorder()

			f.webhookHandler(w, req)

			assert.Equal(t, test.expectedStatusCode, w.Result().StatusCode)

			tb.Kill(nil)
			require.NoError(t, tb.Wait())

			assert.Equal(t, test.eventCount, eventCount)
		})
	}
}

func TestMaxBodySizeDefault(t *testing.T) {
	cfg, err := ConfigurationFromYAML([]byte(`source: k8s-audit
listen_addr: 127.0.0.1
listen_port: 1234
webhook_path: /k8s-audit`))
	require.NoError(t, err)
	require.NotNil(t, cfg.MaxBodySize)
	assert.Equal(t, int64(10*1024*1024), *cfg.MaxBodySize)
}

func TestMaxBodySizeInvalid(t *testing.T) {
	_, err := ConfigurationFromYAML([]byte(`source: k8s-audit
listen_addr: 127.0.0.1
listen_port: 1234
webhook_path: /k8s-audit
max_body_size: 0`))
	cstest.RequireErrorContains(t, err, "max_body_size must be positive")
}
