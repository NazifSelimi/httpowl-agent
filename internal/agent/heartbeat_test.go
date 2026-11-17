package agent

import "testing"

// A failing nginx helper must reach the dashboard, not only the agent log.
func TestHeartbeatReportsSiteBlockError(t *testing.T) {
	a := &Agent{fw: noFirewall{}, botWatch: newBotWatcher()}
	if hb := a.heartbeatBody(); hb.SiteBlocksError != "" {
		t.Fatalf("error without a failure: %q", hb.SiteBlocksError)
	}
	a.rs.siteErr = "nginx rejected the website block list, kept the old one: unknown directive"
	if hb := a.heartbeatBody(); hb.SiteBlocksError != a.rs.siteErr {
		t.Fatalf("got %q", hb.SiteBlocksError)
	}
}
