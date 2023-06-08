package cwhub

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jarcoal/httpmock"
)

func TestDownladFile(t *testing.T) {
	examplePath := "./example.txt"
	defer os.Remove(examplePath)

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
	err := downloadFile("https://example.com/xx", examplePath)
	assert.NoError(t, err)
	content, err := os.ReadFile(examplePath)
	assert.Equal(t, "example content oneoneone", string(content))
	assert.NoError(t, err)
	//bad uri
	err = downloadFile("https://zz.com", examplePath)
	assert.Error(t, err)
	//404
	err = downloadFile("https://example.com/x", examplePath)
	assert.Error(t, err)
	//bad target
	err = downloadFile("https://example.com/xx", "")
	assert.Error(t, err)
}
