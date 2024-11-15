package clilapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func TestPrepareAPIURL_NoProtocol(t *testing.T) {
	url, err := prepareAPIURL(nil, "localhost:81")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:81/", url.String())
}

func TestPrepareAPIURL_Http(t *testing.T) {
	url, err := prepareAPIURL(nil, "http://localhost:81")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:81/", url.String())
}

func TestPrepareAPIURL_Https(t *testing.T) {
	url, err := prepareAPIURL(nil, "https://localhost:81")
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:81/", url.String())
}

func TestPrepareAPIURL_UnixSocket(t *testing.T) {
	url, err := prepareAPIURL(nil, "/path/socket")
	require.NoError(t, err)
	assert.Equal(t, "/path/socket/", url.String())
}

func TestPrepareAPIURL_Empty(t *testing.T) {
	_, err := prepareAPIURL(nil, "")
	require.Error(t, err)
}

func TestPrepareAPIURL_Empty_ConfigOverride(t *testing.T) {
	url, err := prepareAPIURL(&csconfig.LocalApiClientCfg{
		Credentials: &csconfig.ApiCredentialsCfg{
			URL: "localhost:80",
		},
	}, "")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:80/", url.String())
}
