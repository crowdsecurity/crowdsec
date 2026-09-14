package parser

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/dnscache"
)

// fakePTRResolver implements dnscache.Resolver from an in-memory map so the
// test never hits real DNS. ptrCalls lets the test assert caching.
type fakePTRResolver struct {
	ptr      map[string][]string
	ptrCalls atomic.Int32
}

func (f *fakePTRResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.ptrCalls.Add(1)

	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}

	return names, nil
}

func (*fakePTRResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "not implemented"}
}

func TestReverseDNS(t *testing.T) {
	resolver := &fakePTRResolver{
		ptr: map[string][]string{"1.1.1.1": {"one.one.one.one."}},
	}
	dnscache.SetResolver(resolver)
	dnscache.Purge()
	t.Cleanup(func() {
		dnscache.SetResolver(net.DefaultResolver)
		dnscache.Purge()
	})

	plog := log.NewEntry(log.New())

	// the raw PTR name is exposed, trailing dot included (scenarios depend
	// on this format)
	ret, err := reverse_dns("1.1.1.1", nil, plog)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"reverse_dns": "one.one.one.one."}, ret)

	// repeated resolutions are served from the cache
	_, err = reverse_dns("1.1.1.1", nil, plog)
	require.NoError(t, err)
	assert.Equal(t, int32(1), resolver.ptrCalls.Load(), "second call must be served from cache")

	// failure and junk inputs are not errors, just no enrichment
	for _, field := range []string{"", "not-an-ip", "192.0.2.1"} {
		ret, err = reverse_dns(field, nil, plog)
		require.NoError(t, err)
		assert.Nil(t, ret, "field %q must not enrich", field)
	}
}
