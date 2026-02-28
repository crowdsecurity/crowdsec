package allowlists

import (
	"net/netip"
	"testing"

	log "github.com/sirupsen/logrus"
)

func BenchmarkIsAllowlisted_Small(b *testing.B) {
	a := NewAppsecAllowlist(log.NewEntry(log.New()))

	// Simulate small allowlist by manually adding entries
	for i := range 10 {
		prefix := netip.MustParsePrefix("192.168.0.0/24")
		ip := prefix.Addr()
		for range i {
			ip = ip.Next()
		}
		a.trie.Insert(netip.PrefixFrom(ip, 32))
		a.meta[netip.PrefixFrom(ip, 32).String()] = &metadata{
			Description:   "test",
			AllowlistName: "test-list",
		}
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = a.IsAllowlisted("192.168.0.5")
	}
}

func BenchmarkIsAllowlisted_Large(b *testing.B) {
	a := NewAppsecAllowlist(log.NewEntry(log.New()))

	// Simulate large allowlist
	for i := range 1000 {
		prefix := netip.MustParsePrefix("192.168.0.0/24")
		ip := prefix.Addr()
		for range i {
			ip = ip.Next()
		}
		a.trie.Insert(netip.PrefixFrom(ip, 32))
		a.meta[netip.PrefixFrom(ip, 32).String()] = &metadata{
			Description:   "test",
			AllowlistName: "test-list",
		}
	}
	a.trie.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	a.meta["10.0.0.0/8"] = &metadata{
		Description:   "test-range",
		AllowlistName: "test-list",
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = a.IsAllowlisted("10.0.0.1")
	}
}

func BenchmarkIsAllowlisted_NotInList(b *testing.B) {
	a := NewAppsecAllowlist(log.NewEntry(log.New()))

	// Add 1000 entries
	for i := range 1000 {
		prefix := netip.MustParsePrefix("192.168.0.0/24")
		ip := prefix.Addr()
		for range i {
			ip = ip.Next()
		}
		a.trie.Insert(netip.PrefixFrom(ip, 32))
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = a.IsAllowlisted("203.0.113.1")
	}
}
