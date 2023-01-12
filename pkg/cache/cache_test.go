package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateSetGet(t *testing.T) {
	err := CacheInit(CacheCfg{Name: "test", Size: 100, TTL: 1 * time.Second})
	assert.Empty(t, err)
	//set & get
	err = SetKey("test", "testkey0", "testvalue1", nil)
	assert.Empty(t, err)

	ret, err := GetKey("test", "testkey0")
	assert.Equal(t, "testvalue1", ret)
	assert.Empty(t, err)
	//re-set
	err = SetKey("test", "testkey0", "testvalue2", nil)
	assert.Empty(t, err)
	assert.Equal(t, "testvalue1", ret)
	assert.Empty(t, err)
	//expire
	time.Sleep(1500 * time.Millisecond)
	ret, err = GetKey("test", "testkey0")
	assert.Equal(t, "", ret)
	assert.Empty(t, err)
}
