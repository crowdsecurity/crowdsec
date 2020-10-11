package apiserver

import (
	"net"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"
)

func TestIP2Int(t *testing.T) {
	ipInt := controllers.IP2Int(net.ParseIP("127.0.0.1"))
	assert.Equal(t, uint32(2130706433), ipInt)

	ipInt = controllers.IP2Int([]byte{127, 0, 0, 1})
	assert.Equal(t, uint32(2130706433), ipInt)
}

func TestInt2IP(t *testing.T) {
	IP := controllers.Int2ip(uint32(2130706433))
	assert.Equal(t, "127.0.0.1", IP.String())
}

func TestIsIPv4(t *testing.T) {
	IsIpv4 := controllers.IsIpv4("127.0.0.1")
	assert.Equal(t, true, IsIpv4)

	IsIpv4 = controllers.IsIpv4("127.0.0")
	assert.Equal(t, false, IsIpv4)
}

func TestLastAddress(t *testing.T) {
	_, ipv4Net, err := net.ParseCIDR("192.168.0.1/24")
	if err != nil {
		log.Fatal(err)
	}

	lastAddress := controllers.LastAddress(ipv4Net)
	assert.Equal(t, "192.168.0.255", lastAddress.String())
}

func TestGetIpsFromIpRange(t *testing.T) {
	IPStart, IPEnd, err := controllers.GetIpsFromIpRange("192.168.0.1/65")
	assert.Equal(t, "'192.168.0.1/65' is not a valid CIDR", err.Error())
	assert.Equal(t, int64(0), IPStart)
	assert.Equal(t, int64(0), IPEnd)

	IPStart, IPEnd, err = controllers.GetIpsFromIpRange("192.168.0.1/24")
	assert.Equal(t, nil, err)
	assert.Equal(t, int64(3232235520), IPStart)
	assert.Equal(t, int64(3232235775), IPEnd)
}
