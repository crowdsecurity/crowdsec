package v1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/hook"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// insertBeforeCreate makes the next create of name lose a race to a concurrent insert.
func insertBeforeCreate(dbClient *database.Client, name, rowAPIKey, rowAuthType string) *bool {
	inserted := false

	dbClient.Ent.Bouncer.Use(func(next ent.Mutator) ent.Mutator {
		return hook.BouncerFunc(func(ctx context.Context, m *ent.BouncerMutation) (ent.Value, error) {
			if n, _ := m.Name(); !inserted && m.Op().Is(ent.OpCreate) && n == name {
				inserted = true
				apiKey, _ := m.APIKey()
				ip, _ := m.IPAddress()
				authType, _ := m.AuthType()

				if rowAPIKey != "" {
					apiKey = rowAPIKey
				}

				if rowAuthType != "" {
					authType = rowAuthType
				}

				if _, err := m.Client().Bouncer.Create().
					SetName(name).
					SetAPIKey(apiKey).
					SetRevoked(false).
					SetIPAddress(ip).
					SetAuthType(authType).
					SetAutoCreated(true).
					Save(ctx); err != nil {
					return nil, err
				}
			}

			return next.Mutate(ctx, m)
		})
	})

	return &inserted
}

func testClientCert(t *testing.T, cn, ou string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func TestAPIKeyMiddlewareAutoCreatedBouncer(t *testing.T) {
	const (
		apiKey   = "testkey123"
		clientIP = "4.3.2.1"
	)

	tests := []struct {
		name        string
		tls         bool
		concurrent  bool
		rowAPIKey   string
		rowAuthType string
		wantAbort   bool
	}{
		{name: "api key, new ip"},
		{name: "api key, new ip, row created concurrently", concurrent: true},
		{name: "api key, name taken concurrently by another key", concurrent: true, rowAPIKey: HashSHA512("otherkey"), wantAbort: true},
		{name: "tls, new ip", tls: true},
		{name: "tls, new ip, row created concurrently", tls: true, concurrent: true},
		{name: "tls, name taken concurrently by an api key bouncer", tls: true, concurrent: true, rowAuthType: types.ApiKeyAuthType, wantAbort: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			dbClient, err := database.NewClient(ctx, &csconfig.DatabaseCfg{Type: "sqlite", DbPath: ":memory:"}, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = dbClient.Close() })

			_, err = dbClient.CreateBouncer(ctx, "test", "127.0.0.1", HashSHA512(apiKey), types.ApiKeyAuthType, false)
			require.NoError(t, err)

			a := NewAPIKey(dbClient)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", http.NoBody)
			c.Request.Header.Set("User-Agent", "crowdsec-test/v1.0.0")
			c.Request.RemoteAddr = clientIP + ":1234"

			wantName := "test@" + clientIP

			if tc.tls {
				a.TlsAuth, err = NewTLSAuth([]string{"bouncer-ou"}, "", time.Minute, log.NewEntry(log.StandardLogger()))
				require.NoError(t, err)

				cert := testClientCert(t, "tlsbouncer", "bouncer-ou")
				c.Request.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert},
					VerifiedChains:   [][]*x509.Certificate{{cert}},
				}
				wantName = "tlsbouncer@" + clientIP
			} else {
				c.Request.Header.Set(APIKeyHeader, apiKey)
			}

			var inserted *bool
			if tc.concurrent {
				inserted = insertBeforeCreate(dbClient, wantName, tc.rowAPIKey, tc.rowAuthType)
			}

			a.Middleware(c)

			if inserted != nil {
				require.True(t, *inserted, "the concurrent insert never ran")
			}

			if tc.wantAbort {
				require.True(t, c.IsAborted())
				require.Equal(t, http.StatusForbidden, w.Code)

				return
			}

			require.False(t, c.IsAborted(), "request rejected with %d: %s", w.Code, w.Body.String())

			got, ok := c.Get(BouncerContextKey)
			require.True(t, ok)
			require.Equal(t, wantName, got.(*ent.Bouncer).Name)
		})
	}
}
