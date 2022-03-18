package types

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jarcoal/httpmock"
)

func TestDownladFile(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	//OK
	httpmock.RegisterResponder(
		"GET",
		"https://example.com/xx",
		httpmock.NewStringResponder(200, "example content oneoneone"),
	)
	httpmock.RegisterResponder(
		"GET",
		"https://example.com/x",
		httpmock.NewStringResponder(404, "not found"),
	)
	err := downloadFile("https://example.com/xx", "./example.txt")
	assert.NoError(t, err)
	content, err := ioutil.ReadFile("./example.txt")
	assert.Equal(t, "example content oneoneone", string(content))
	//bad uri
	err = downloadFile("https://zz.com", "./example.txt")
	assert.Error(t, err)
	//404
	err = downloadFile("https://example.com/x", "./example.txt")
	assert.Error(t, err)
	//bad target
	err = downloadFile("https://example.com/xx", "")
	assert.Error(t, err)
}
