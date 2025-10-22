package kubernetesauditacquisition

import (
	"fmt"
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
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestBadConfiguration(t *testing.T) {
	tests := []struct {
		config      string
		name        string
		expectedErr string
	}{
		{
			name: "unknown field",
			config: `source: k8s-audit
foobar: asd.log`,
			expectedErr: `[2:1] unknown field "foobar"`,
		},
		{
			name:        "missing listen_addr",
			config:      `source: k8s-audit`,
			expectedErr: "listen_addr cannot be empty",
		},
		{
			name: "missing listen_port",
			config: `source: k8s-audit
listen_addr: 0.0.0.0`,
			expectedErr: "listen_port cannot be empty",
		},
		{
			name: "mismatched types",
			config: `
source: k8s-audit
listen_addr: 0.0.0.0
listen_port: true
`,
			expectedErr: `[4:14] cannot unmarshal bool into Go struct field KubernetesAuditConfiguration.ListenPort of type int`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := KubernetesAuditSource{}

			err := f.UnmarshalConfig([]byte(test.config))
			cstest.RequireErrorContains(t, err, test.expectedErr)
		})
	}
}

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

	subLogger := log.WithField("type", "k8s-audit")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := make(chan types.Event)
			tb := &tomb.Tomb{}

			f := KubernetesAuditSource{}

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

	subLogger := log.WithField("type", "k8s-audit")

	for idx, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := make(chan types.Event)
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

			f := KubernetesAuditSource{}

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
