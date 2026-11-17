package agent

import (
	"net/netip"
	"testing"
	"time"

	"github.com/NazifSelimi/httpowl-agent/internal/wire"
)

func TestSafeBlocksNeverCoversAllowed(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("127.0.0.1")}
	got := safeBlocks([]string{
		"203.0.113.0/24",  // contains an allowed IP -> dropped
		"198.51.100.7",    // plain IP -> /32
		"10.0.0.0/8",      // private -> dropped
		"0.0.0.0/0",       // too broad -> dropped
		"2001:db8::/16",   // too broad -> dropped
		"192.0.2.0/24",    // ok
		"198.51.100.7/32", // duplicate
		"garbage",
	}, allow)
	want := []string{"192.0.2.0/24", "198.51.100.7/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestBotWatcher(t *testing.T) {
	b := newBotWatcher()
	b.see(wire.Request{IP: "192.0.2.1", UA: "AhrefsBot/7.0"})
	if srv, _ := b.activeIPs(); len(srv) != 0 {
		t.Fatal("blocked without a pattern")
	}
	b.setPatterns([]string{"ahrefsbot"}, nil)
	b.see(wire.Request{IP: "192.0.2.1", UA: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"})
	b.see(wire.Request{IP: "192.0.2.2", UA: "Mozilla/5.0 Chrome"})
	if ips, _ := b.activeIPs(); len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("got %v", ips)
	}
	b.ips[botKey{"", "192.0.2.1"}] = time.Now().Add(-time.Second)
	if srv, _ := b.activeIPs(); len(srv) != 0 {
		t.Fatal("expired block kept")
	}
}

func TestBotWatcherPerSite(t *testing.T) {
	b := newBotWatcher()
	b.setPatterns(nil, []wire.SiteRules{{Domains: []string{"a.com", "www.a.com"}, BotPatterns: []string{"semrush"}}})
	b.see(wire.Request{IP: "192.0.2.1", Host: "www.a.com", UA: "SemrushBot"})
	b.see(wire.Request{IP: "192.0.2.2", Host: "b.com", UA: "SemrushBot"}) // other website: not blocked
	srv, sites := b.activeIPs()
	if len(srv) != 0 || len(sites["a.com"]) != 1 || sites["a.com"][0] != "192.0.2.1" || len(sites) != 1 {
		t.Fatalf("server %v sites %v", srv, sites)
	}
	b.setPatterns(nil, nil) // rule removed: block lifted
	if _, sites := b.activeIPs(); len(sites) != 0 {
		t.Fatalf("not lifted: %v", sites)
	}
}
