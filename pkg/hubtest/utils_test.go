package hubtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPathNotContained(t *testing.T) {
	assert.Nil(t, checkPathNotContained("/foo", "/bar"))
	assert.Nil(t, checkPathNotContained("/foo/bar", "/foo"))
	assert.Nil(t, checkPathNotContained("/foo/bar", "/"))
	assert.Nil(t, checkPathNotContained("/path/to/somewhere", "/path/to/somewhere-else"))
	assert.Nil(t, checkPathNotContained("~/.local/path/to/somewhere", "~/.local/path/to/somewhere-else"))
	assert.NotNil(t, checkPathNotContained("/foo", "/foo/bar"))
	assert.NotNil(t, checkPathNotContained("/", "/foo"))
	assert.NotNil(t, checkPathNotContained("/", "/foo/bar/baz"))
}
