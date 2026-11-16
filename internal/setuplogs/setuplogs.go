// Package setuplogs adds a second access log that records the domain of every
// visit, so one agent can tell the websites on a server apart.
//
// It only ever ADDS one file per web server (never edits existing config),
// tests the config before reloading, removes its file again if the test
// fails, and `--undo` removes it any time. Callers must ask the person first.
package setuplogs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Server describes how to add the domain log to one web server.
type Server struct {
	Name     string
	ConfFile string   // the one file we add
	Content  string   // its content
	LogFile  string   // where visits with domains are written
	Test     []string // config test command
	Reload   []string // reload command
	Enable   []string // optional: enable the conf (Debian a2enconf)
	Disable  []string // optional: undo Enable
	Notes    []string // things the person should know (e.g. sites that keep their own log)
}

const header = "# Added by HTTPowl (httpowl-agent setup-logs). Remove with: sudo httpowl-agent setup-logs --undo\n" +
	"# A second access log that also records the domain, so HTTPowl can tell your websites apart.\n"

// Nginx plans the nginx change, or returns an error when it can't be done safely.
func Nginx() (*Server, error) {
	main, err := os.ReadFile("/etc/nginx/nginx.conf")
	if err != nil {
		return nil, fmt.Errorf("nginx config not found: %w", err)
	}
	if !strings.Contains(string(main), "/etc/nginx/conf.d/*.conf") {
		return nil, errors.New("/etc/nginx/nginx.conf does not include /etc/nginx/conf.d/*.conf; add the HTTPowl log by hand (see the README)")
	}
	s := &Server{
		Name:     "nginx",
		ConfFile: "/etc/nginx/conf.d/httpowl-log.conf",
		LogFile:  "/var/log/nginx/httpowl.log",
		Content: header +
			"log_format httpowl '$host $remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" rt=$request_time';\n" +
			"access_log /var/log/nginx/httpowl.log httpowl;\n",
		Test:   []string{"nginx", "-t"},
		Reload: []string{"systemctl", "reload", "nginx"},
	}
	// nginx: a server block with its own access_log does not inherit http-level logs.
	if own := serversWithOwnLog(); len(own) > 0 {
		s.Notes = append(s.Notes, "These config files set their own access_log, so their visits won't be in the HTTPowl log:")
		for _, f := range own {
			s.Notes = append(s.Notes, "  "+f+"  (add: access_log /var/log/nginx/httpowl.log httpowl;)")
		}
	}
	return s, nil
}

// Apache plans the Apache change (Debian apache2 or RHEL httpd). GlobalLog covers every virtual host.
func Apache() (*Server, error) {
	const format = "LogFormat \"%v %a %l %u %t \\\"%r\\\" %>s %O \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" httpowl\n"
	if _, err := os.Stat("/etc/apache2/conf-available"); err == nil {
		return &Server{
			Name: "apache", ConfFile: "/etc/apache2/conf-available/httpowl-log.conf", LogFile: "/var/log/apache2/httpowl.log",
			Content: header + format + "GlobalLog ${APACHE_LOG_DIR}/httpowl.log httpowl\n",
			Test:    []string{"apachectl", "configtest"}, Reload: []string{"apachectl", "graceful"},
			Enable: []string{"a2enconf", "-q", "httpowl-log"}, Disable: []string{"a2disconf", "-q", "httpowl-log"},
		}, nil
	}
	if _, err := os.Stat("/etc/httpd/conf.d"); err == nil {
		return &Server{
			Name: "apache", ConfFile: "/etc/httpd/conf.d/httpowl-log.conf", LogFile: "/var/log/httpd/httpowl.log",
			Content: header + format + "GlobalLog logs/httpowl.log httpowl\n",
			Test:    []string{"apachectl", "configtest"}, Reload: []string{"apachectl", "graceful"},
		}, nil
	}
	return nil, errors.New("Apache config folder not found")
}

// For returns the plan for a detected server name, or nil when it needs nothing
// (Caddy, Traefik and IIS already log the domain).
func For(name string) (*Server, error) {
	switch name {
	case "nginx":
		return Nginx()
	case "apache":
		return Apache()
	}
	return nil, nil
}

// Installed reports whether our file is already in place.
func (s *Server) Installed() bool {
	_, err := os.Stat(s.ConfFile)
	return err == nil
}

// Describe is the plain-words text shown before asking for permission.
func (s *Server) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTPowl wants to add ONE new file for %s, so it can tell your websites apart:\n\n  %s\n\n", s.Name, s.ConfFile)
	for _, line := range strings.Split(strings.TrimSpace(s.Content), "\n") {
		b.WriteString("    " + line + "\n")
	}
	fmt.Fprintf(&b, "\nIt writes a second log (%s) with the domain of each visit. Your existing\n", s.LogFile)
	b.WriteString("config and logs are not changed. The config is tested before reloading; if the\n")
	b.WriteString("test fails the file is removed again. Undo any time: sudo httpowl-agent setup-logs --undo\n")
	for _, n := range s.Notes {
		b.WriteString("\n" + n)
	}
	return b.String()
}

// Apply adds the file, tests, reloads. On a failed test it removes the file and returns the test output.
func (s *Server) Apply() error {
	if s.Installed() {
		return nil
	}
	if err := os.WriteFile(s.ConfFile, []byte(s.Content), 0o644); err != nil {
		return err
	}
	if s.Enable != nil {
		if out, err := run(s.Enable); err != nil {
			_ = os.Remove(s.ConfFile)
			return fmt.Errorf("enabling the config failed, nothing changed: %s", out)
		}
	}
	if out, err := run(s.Test); err != nil {
		s.removeFile()
		return fmt.Errorf("%s config test failed, so the HTTPowl file was removed again and nothing changed:\n%s", s.Name, out)
	}
	if out, err := run(s.Reload); err != nil {
		return fmt.Errorf("config is valid but the reload failed: %s", out)
	}
	return nil
}

// Undo removes the file and reloads.
func (s *Server) Undo() error {
	if !s.Installed() {
		return nil
	}
	s.removeFile()
	if out, err := run(s.Test); err != nil {
		return fmt.Errorf("%s config test failed after removing the HTTPowl file:\n%s", s.Name, out)
	}
	if out, err := run(s.Reload); err != nil {
		return fmt.Errorf("reload failed: %s", out)
	}
	return nil
}

func (s *Server) removeFile() {
	if s.Disable != nil {
		_, _ = run(s.Disable)
	}
	_ = os.Remove(s.ConfFile)
}

func run(cmd []string) (string, error) {
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// serversWithOwnLog lists nginx site files that set access_log inside a server block.
func serversWithOwnLog() []string {
	var out []string
	files, _ := filepath.Glob("/etc/nginx/sites-enabled/*")
	more, _ := filepath.Glob("/etc/nginx/conf.d/*.conf")
	for _, f := range append(files, more...) {
		if strings.HasSuffix(f, "httpowl-log.conf") {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "access_log") && !strings.Contains(line, " off") && !strings.Contains(line, "httpowl.log") {
				out = append(out, f)
				break
			}
		}
		fh.Close()
	}
	return out
}
