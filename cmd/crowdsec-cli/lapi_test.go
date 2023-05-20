package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrepareApiURl_NoProtocol(t *testing.T) {

	url, err := prepareApiURl(nil, "localhost:81")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:81/", url.String())

}

func TestPrepareApiURl_Http(t *testing.T) {

	url, err := prepareApiURl(nil, "http://localhost:81")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:81/", url.String())

}

func TestPrepareApiURl_Https(t *testing.T) {

	url, err := prepareApiURl(nil, "https://localhost:81")
	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:81/", url.String())

}

func TestPrepareApiURl_UnixSocket(t *testing.T) {

	url, err := prepareApiURl(nil, "/path/socket")
	assert.NoError(t, err)
	assert.Equal(t, "/path/socket/", url.String())

}

func TestPrepareApiURl_Empty(t *testing.T) {

	_, err := prepareApiURl(nil, "")
	assert.Error(t, err)

}

func TestPrepareApiURl_Empty_ConfigOverride(t *testing.T) {

	url, err := prepareApiURl(&csconfig.LocalApiClientCfg{
		Credentials: &csconfig.ApiCredentialsCfg{
			URL: "localhost:80",
		},
	}, "")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:80/", url.String())

}
