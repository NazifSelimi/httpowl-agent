// Package detect finds which web servers run here and where their access logs are.
package detect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/NazifSelimi/httpowl-agent/internal/agent/tail"
)

type Server struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
}

// Known log locations per server.
var known = []Server{
	{"nginx", []string{"/var/log/nginx/*access*.log", "/usr/local/nginx/logs/access.log"}},
	{"apache", []string{"/var/log/apache2/*access*.log", "/var/log/httpd/*access_log", "/var/log/httpd/*access*.log", "/usr/local/apache2/logs/access_log"}},
	{"litespeed", []string{"/usr/local/lsws/logs/access.log", "/usr/local/lsws/logs/*access*.log"}},
	{"caddy", []string{"/var/log/caddy/*.log"}},
	{"traefik", []string{"/var/log/traefik/access.log", "/var/log/traefik/*access*.log"}},
	{"iis", []string{`C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log`}},
}

// processNames maps running process names to servers (Linux /proc).
var processNames = map[string]string{
	"nginx": "nginx", "apache2": "apache", "httpd": "apache", "litespeed": "litespeed",
	"lshttpd": "litespeed", "openlitespeed": "litespeed", "caddy": "caddy", "traefik": "traefik",
}

// domainLogs are the logs written by `httpowl-agent setup-logs` (they include the domain).
// When one exists it replaces the server's default logs, so no visit is counted twice.
var domainLogs = map[string]string{
	"nginx":  "/var/log/nginx/httpowl.log",
	"apache": "/var/log/apache2/httpowl.log",
}

func init() {
	if _, err := os.Stat("/etc/httpd"); err == nil { // RHEL-style Apache
		domainLogs["apache"] = "/var/log/httpd/httpowl.log"
	}
}

// DomainLog returns the HTTPowl domain log for a server, if setup-logs created it.
func DomainLog(server string) string {
	if p, ok := domainLogs[server]; ok {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Detect returns servers that are running or have log files.
func Detect() []Server {
	running := runningServers()
	var out []Server
	for _, s := range known {
		if s.Name == "iis" && runtime.GOOS != "windows" {
			continue
		}
		if len(tail.Files(s.Patterns)) > 0 || running[s.Name] {
			if p := DomainLog(s.Name); p != "" {
				s.Patterns = []string{p}
			}
			out = append(out, s)
		}
	}
	return out
}

// Patterns flattens the patterns of the given servers.
func Patterns(ss []Server) []string {
	var p []string
	for _, s := range ss {
		p = append(p, s.Patterns...)
	}
	return p
}

// Names lists server names.
func Names(ss []Server) []string {
	var n []string
	for _, s := range ss {
		n = append(n, s.Name)
	}
	return n
}

func runningServers() map[string]bool {
	found := map[string]bool{}
	dirs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, d := range dirs {
		b, err := os.ReadFile(d)
		if err != nil {
			continue
		}
		if s, ok := processNames[strings.TrimSpace(string(b))]; ok {
			found[s] = true
		}
	}
	return found
}
