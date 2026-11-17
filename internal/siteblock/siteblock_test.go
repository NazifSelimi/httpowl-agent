package siteblock

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	got := Render([]Site{
		{Domains: []string{"tessa.mk", "www.tessa.mk"}, Block: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32"), netip.MustParsePrefix("2001:db8::/48")}},
		{Domains: []string{"oya.com.mk"}}, // nothing blocked: not listed
		{Domains: []string{"evil.com; return 200", "Bad Host"}, Block: []netip.Prefix{netip.MustParsePrefix("5.6.7.8/32")}},
	})
	for _, want := range []string{
		"geo $remote_addr $httpowl_b0 {\n    default 0;\n    1.2.3.4/32 1;\n    2001:db8::/48 1;\n}\n",
		"map $host $httpowl_block {\n    default 0;\n    tessa.mk $httpowl_b0;\n    www.tessa.mk $httpowl_b0;\n}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing:\n%s\ngot:\n%s", want, got)
		}
	}
	for _, bad := range []string{"oya", "evil", "5.6.7.8", "$httpowl_b1"} {
		if strings.Contains(got, bad) {
			t.Errorf("should not contain %q:\n%s", bad, got)
		}
	}
	if empty := Render(nil); !strings.Contains(empty, "map $host $httpowl_block {\n    default 0;\n}") {
		t.Errorf("empty render: %s", empty)
	}
}

func TestInsertIncludes(t *testing.T) {
	src := `upstream app {
    server 127.0.0.1:8080;
}
server {
    listen 80;
    server_name a.com; # server {
    location / { proxy_pass http://app; }
}

server { # ssl
	listen 443 ssl;
	if ($host = a.com) { return 301 https://$host$request_uri; }
}
server
{
    listen 81;
}
`
	out, added, missed := insertIncludes(src)
	if added != 2 || !missed {
		t.Fatalf("added=%d missed=%v\n%s", added, missed, out)
	}
	if !strings.Contains(out, "server {\n    "+includeDir+"\n    listen 80;") {
		t.Errorf("first block not changed:\n%s", out)
	}
	if !strings.Contains(out, "server { # ssl\n    "+includeDir+"\n\tlisten 443") {
		t.Errorf("second block not changed:\n%s", out)
	}
	if strings.Count(out, includeDir) != 2 {
		t.Errorf("upstream or nested server touched:\n%s", out)
	}
	again, added2, _ := insertIncludes(out)
	if added2 != 0 || again != out {
		t.Errorf("not idempotent: added %d", added2)
	}
	if removeIncludes(out) != src {
		t.Errorf("undo does not restore the original:\n%s", removeIncludes(out))
	}
}

func TestStatus(t *testing.T) {
	f := filepath.Join(t.TempDir(), "status")
	if err := statusAt(f); err != nil {
		t.Fatalf("helper not run yet is not an error: %v", err)
	}
	_ = os.WriteFile(f, []byte("ok\n"), 0o600)
	if err := statusAt(f); err != nil {
		t.Fatalf("ok: %v", err)
	}
	_ = os.WriteFile(f, []byte("nginx reload failed: Job failed\n"), 0o600)
	if err := statusAt(f); err == nil || err.Error() != "nginx reload failed: Job failed" {
		t.Fatalf("got %v", err)
	}
}
