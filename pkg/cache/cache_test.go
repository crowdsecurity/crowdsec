package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSetGet(t *testing.T) {
	err := CacheInit(CacheCfg{Name: "test", Size: 100, TTL: 1 * time.Second})
	require.NoError(t, err)
	//set & get
	err = SetKey("test", "testkey0", "testvalue1", nil)
	require.NoError(t, err)

	ret, err := GetKey("test", "testkey0")
	assert.Equal(t, "testvalue1", ret)
	require.NoError(t, err)
	//re-set
	err = SetKey("test", "testkey0", "testvalue2", nil)
	require.NoError(t, err)
	assert.Equal(t, "testvalue1", ret)
	require.NoError(t, err)
	//expire
	time.Sleep(1500 * time.Millisecond)
	ret, err = GetKey("test", "testkey0")
	assert.Equal(t, "", ret)
	require.NoError(t, err)
}
