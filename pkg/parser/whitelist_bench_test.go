package parser

import (
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func BenchmarkCheckIPsWL_SmallAllowlist(b *testing.B) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
		Whitelist: Whitelist{
			Reason: "test",
			B_Trie: new(bart.Lite),
		},
	}

	// Small allowlist: 10 IPs + 2 CIDRs
	for i := range 10 {
		ip := netip.MustParseAddr("192.168.0.1")
		for range i {
			ip = ip.Next()
		}
		node.Whitelist.B_Trie.Insert(netip.PrefixFrom(ip, 32))
	}
	node.Whitelist.B_Trie.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	node.Whitelist.B_Trie.Insert(netip.MustParsePrefix("172.16.0.0/12"))

	event := &pipeline.Event{
		Meta: map[string]string{
			"source_ip": "192.168.0.5",
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = node.CheckIPsWL(event)
	}
}

func BenchmarkCheckIPsWL_MediumAllowlist(b *testing.B) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
		Whitelist: Whitelist{
			Reason: "test",
			B_Trie: new(bart.Lite),
		},
	}

	// Medium allowlist: 100 IPs + 10 CIDRs
	for i := range 100 {
		ip := netip.MustParseAddr("192.168.0.1")
		for range i {
			ip = ip.Next()
		}
		node.Whitelist.B_Trie.Insert(netip.PrefixFrom(ip, 32))
	}
	for i := range 10 {
		base := netip.MustParseAddr("10.0.0.0")
		for range i {
			base = base.Next()
		}
		node.Whitelist.B_Trie.Insert(netip.PrefixFrom(base, 24))
	}

	event := &pipeline.Event{
		Meta: map[string]string{
			"source_ip": "192.168.0.50",
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = node.CheckIPsWL(event)
	}
}

func BenchmarkCheckIPsWL_LargeAllowlist(b *testing.B) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
		Whitelist: Whitelist{
			Reason: "test",
			B_Trie: new(bart.Lite),
		},
	}

	// Large allowlist: 1000 IPs + 50 CIDRs
	for i := range 1000 {
		ip := netip.MustParseAddr("192.168.0.1")
		for range i {
			ip = ip.Next()
		}
		node.Whitelist.B_Trie.Insert(netip.PrefixFrom(ip, 32))
	}
	for i := range 50 {
		base := netip.MustParseAddr("10.0.0.0")
		for range i * 256 {
			base = base.Next()
		}
		node.Whitelist.B_Trie.Insert(netip.PrefixFrom(base, 24))
	}

	event := &pipeline.Event{
		Meta: map[string]string{
			"source_ip": "192.168.1.100",
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = node.CheckIPsWL(event)
	}
}

func BenchmarkCheckIPsWL_NotInAllowlist(b *testing.B) {
	node := &Node{
		Logger: log.NewEntry(log.New()),
		Whitelist: Whitelist{
			Reason: "test",
			B_Trie: new(bart.Lite),
		},
	}

	// Add 1000 IPs but test with IP not in list
	for i := range 1000 {
		ip := netip.MustParseAddr("192.168.0.1")
		for range i {
			ip = ip.Next()
		}
		node.Whitelist.B_Trie.Insert(netip.PrefixFrom(ip, 32))
	}

	event := &pipeline.Event{
		Meta: map[string]string{
			"source_ip": "203.0.113.1", // Not in allowlist
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = node.CheckIPsWL(event)
	}
}
