package csnet

import (
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type IPAddrSize int

const (
	IPv4Size IPAddrSize = 4
	IPv6Size IPAddrSize = 16
)

type IP struct {
	size IPAddrSize
	Addr int64
	Sfx  int64
}

type Range struct {
	Start IP
	End   IP
}

func (r Range) Size() int {
	return int(r.Start.size)
}

func NewRange(anyIP string) (Range, error) {
	size, start_ip, start_sfx, end_ip, end_sfx, err := types.Addr2Ints(anyIP)
	if err != nil {
		return Range{}, err
	}

	return Range{
		Start: IP{
			size: IPAddrSize(size),
			Addr: start_ip,
			Sfx:  start_sfx,
		},
		End: IP{
			size: IPAddrSize(size),
			Addr: end_ip,
			Sfx:  end_sfx,
		},
	}, nil
}
