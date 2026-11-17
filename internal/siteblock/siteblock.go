// Package siteblock blocks visitors from ONE website on a shared server, by
// having nginx refuse them for that domain only. The firewall can't do this:
// it doesn't know which website a visitor asks for.
//
// Two files, both owned by HTTPowl:
//   - MapFile (http level): which IPs are blocked for which host names.
//     The agent rewrites it on every rule change, tests it, and reloads nginx.
//   - Snippet: `if ($httpowl_block) { return 444; }`, included once in every
//     server block by `httpowl-agent setup-blocks` (after asking).
package siteblock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	MapFile   = "/etc/nginx/conf.d/httpowl-blocks.conf"
	Snippet   = "/etc/nginx/snippets/httpowl-block.conf"
	BackupDir = "/etc/httpowl/backup"

	// The agent runs sandboxed (read-only /etc), so it never touches nginx
	// itself: it writes the wanted blocks as JSON to StagedFile, and a systemd
	// path unit runs `httpowl-agent apply-site-blocks` as root, which renders,
	// tests and reloads, and writes the outcome to StatusFile.
	StagedFile   = "/var/lib/httpowl-agent/site-blocks.json"
	StatusFile   = "/var/lib/httpowl-agent/site-blocks.status"
	PathUnit     = "/etc/systemd/system/httpowl-site-blocks.path"
	ServiceUnit  = "/etc/systemd/system/httpowl-site-blocks.service"
	pathUnitBody = "[Unit]\nDescription=HTTPowl: apply per-website blocks when the agent changes them\n\n" +
		"[Path]\nPathChanged=" + StagedFile + "\n\n[Install]\nWantedBy=multi-user.target\n"
	serviceUnitBody = "[Unit]\nDescription=HTTPowl: write per-website blocks to nginx, test, reload\n\n" +
		"[Service]\nType=oneshot\nExecStart=/usr/local/bin/httpowl-agent apply-site-blocks\n"
	marker     = "# httpowl"
	includeDir = "include " + Snippet + "; " + marker

	snippetBody = "# Added by HTTPowl (httpowl-agent setup-blocks). Remove with: sudo httpowl-agent setup-blocks --undo\n" +
		"# Refuses visitors that are blocked for this website only (list: " + MapFile + ").\n" +
		"if ($httpowl_block) { return 444; }\n"
	mapHeader = "# Managed by httpowl-agent: rewritten on every block change, do not edit.\n" +
		"# Visitors blocked for one website only. Remove with: sudo httpowl-agent setup-blocks --undo\n"
)

// Site is one website's blocked ranges.
type Site struct {
	Domains []string       `json:"domains"`
	Block   []netip.Prefix `json:"block"`
}

// Stage hands the wanted blocks to the root helper (agent side).
// It returns the helper's last outcome: "" when fine.
func Stage(sites []Site) error {
	b, err := json.Marshal(sites)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(StagedFile); err != nil || !bytes.Equal(old, b) {
		if err := os.WriteFile(StagedFile, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Status is the helper's last outcome: nil when the staged blocks are live.
func Status() error {
	b, err := os.ReadFile(StatusFile)
	if err != nil {
		return nil // helper hasn't run yet
	}
	if s := strings.TrimSpace(string(b)); s != "ok" && s != "" {
		return errors.New(s)
	}
	return nil
}

// ApplyStaged is the root helper: render the staged JSON (so only valid map
// syntax ever reaches nginx), write, test, reload, and record the outcome.
func ApplyStaged() error {
	err := applyStaged()
	msg := "ok"
	if err != nil {
		msg = err.Error()
	}
	_ = os.WriteFile(StatusFile, []byte(msg+"\n"), 0o600)
	return err
}

func applyStaged() error {
	b, err := os.ReadFile(StagedFile)
	if err != nil {
		return err
	}
	var sites []Site
	if err := json.Unmarshal(b, &sites); err != nil {
		return fmt.Errorf("bad website block list: %w", err)
	}
	return Write(Render(sites))
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Render builds MapFile's content. Host names that aren't plain domains are
// skipped, so nothing from the server can inject nginx config.
func Render(sites []Site) string {
	var b strings.Builder
	b.WriteString(mapHeader)
	var hosts []string
	hostVar := map[string]string{}
	n := 0
	for _, s := range sites {
		if len(s.Block) == 0 {
			continue
		}
		v := fmt.Sprintf("$httpowl_b%d", n)
		var mine []string
		for _, d := range s.Domains {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if hostRe.MatchString(d) && hostVar[d] == "" {
				hostVar[d] = v
				mine = append(mine, d)
			}
		}
		if len(mine) == 0 {
			continue
		}
		n++
		fmt.Fprintf(&b, "geo $remote_addr %s {\n    default 0;\n", v)
		for _, p := range s.Block {
			fmt.Fprintf(&b, "    %s 1;\n", p.Masked())
		}
		b.WriteString("}\n")
		hosts = append(hosts, mine...)
	}
	sort.Strings(hosts)
	b.WriteString("map $host $httpowl_block {\n    default 0;\n")
	for _, h := range hosts {
		fmt.Fprintf(&b, "    %s %s;\n", h, hostVar[h])
	}
	b.WriteString("}\n")
	return b.String()
}

// Ready reports whether per-website blocks work here: the map and snippet
// exist and at least one server block includes the snippet.
func Ready() bool {
	if !exists(MapFile) || !exists(Snippet) || !exists(PathUnit) {
		return false
	}
	for _, f := range vhostFiles() {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, []byte(includeDir)) {
			return true
		}
	}
	return false
}

// Write replaces MapFile with content, tests nginx and reloads. On a failed
// test the previous file is put back and nginx is not reloaded.
func Write(content string) error {
	old, err := os.ReadFile(MapFile)
	if err != nil {
		return fmt.Errorf("per-website blocks are not set up (run: sudo httpowl-agent setup-blocks)")
	}
	if string(old) == content {
		return nil
	}
	if err := writeAtomic(MapFile, []byte(content)); err != nil {
		return err
	}
	if out, err := run("nginx", "-t"); err != nil {
		_ = writeAtomic(MapFile, old)
		return fmt.Errorf("nginx rejected the website block list, kept the old one: %s", lastLine(out))
	}
	if out, err := run("systemctl", "reload", "nginx"); err != nil {
		return fmt.Errorf("nginx reload failed: %s", lastLine(out))
	}
	return nil
}

// Plan lists the server blocks setup would change.
type Plan struct {
	Files   map[string]int // file → server blocks that will get the include
	Missed  []string       // files with a server block we can't safely find
	Already bool           // already set up everywhere
}

// MakePlan reads the nginx site files. It changes nothing.
func MakePlan() (*Plan, error) {
	main, err := os.ReadFile("/etc/nginx/nginx.conf")
	if err != nil {
		return nil, fmt.Errorf("nginx config not found: %w", err)
	}
	if !strings.Contains(string(main), "/etc/nginx/conf.d/*.conf") {
		return nil, errors.New("/etc/nginx/nginx.conf does not include /etc/nginx/conf.d/*.conf")
	}
	p := &Plan{Files: map[string]int{}}
	for _, f := range vhostFiles() {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		_, added, missed := insertIncludes(string(b))
		if added > 0 {
			p.Files[f] = added
		}
		if missed {
			p.Missed = append(p.Missed, f)
		}
	}
	p.Already = len(p.Files) == 0 && Ready()
	return p, nil
}

// Describe is the plain-words text shown before asking.
func (p *Plan) Describe() string {
	var b strings.Builder
	b.WriteString("HTTPowl wants to let you block a visitor from ONE website without blocking\n")
	b.WriteString("them from your other websites on this server. For that it will:\n\n")
	fmt.Fprintf(&b, "  1. add %s (the blocked-visitors list, empty for now)\n", MapFile)
	fmt.Fprintf(&b, "  2. add %s:\n       if ($httpowl_block) { return 444; }\n", Snippet)
	fmt.Fprintf(&b, "  3. add a small systemd helper (%s + .service) that updates the list,\n", filepath.Base(PathUnit))
	b.WriteString("     tests nginx and reloads it when your blocks change (the agent itself stays read-only)\n")
	b.WriteString("  4. add this one line at the top of each server block:\n")
	fmt.Fprintf(&b, "       %s\n", includeDir)
	names := make([]string, 0, len(p.Files))
	for f := range p.Files {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		fmt.Fprintf(&b, "     - %s (%d server block(s))\n", f, p.Files[f])
	}
	fmt.Fprintf(&b, "\nEach changed file is backed up to %s first. The config is tested\n", BackupDir)
	b.WriteString("before reloading; if the test fails everything is put back. Visitors that are\n")
	b.WriteString("not blocked see no difference. Undo any time: sudo httpowl-agent setup-blocks --undo\n")
	if len(p.Missed) > 0 {
		b.WriteString("\nThese files have a server block written in a way HTTPowl won't edit; add the line by hand:\n")
		for _, f := range p.Missed {
			b.WriteString("  " + f + "\n")
		}
	}
	return b.String()
}

// Apply makes the change. Anything that fails is rolled back.
func (p *Plan) Apply() error {
	stamp := time.Now().Format("20060102-150405")
	if err := os.MkdirAll(BackupDir, 0o700); err != nil {
		return err
	}
	var undo []func()
	rollback := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	if !exists(MapFile) {
		if err := writeAtomic(MapFile, []byte(Render(nil))); err != nil {
			return err
		}
		undo = append(undo, func() { _ = os.Remove(MapFile) })
	}
	if !exists(Snippet) {
		_ = os.MkdirAll(filepath.Dir(Snippet), 0o755)
		if err := writeAtomic(Snippet, []byte(snippetBody)); err != nil {
			rollback()
			return err
		}
		undo = append(undo, func() { _ = os.Remove(Snippet) })
	}
	for f := range p.Files {
		real, err := filepath.EvalSymlinks(f)
		if err != nil {
			rollback()
			return err
		}
		old, err := os.ReadFile(real)
		if err != nil {
			rollback()
			return err
		}
		if err := os.WriteFile(filepath.Join(BackupDir, filepath.Base(real)+"."+stamp), old, 0o600); err != nil {
			rollback()
			return err
		}
		updated, _, _ := insertIncludes(string(old))
		if err := writeAtomic(real, []byte(updated)); err != nil {
			rollback()
			return err
		}
		undo = append(undo, func() { _ = writeAtomic(real, old) })
	}
	if out, err := run("nginx", "-t"); err != nil {
		rollback()
		return fmt.Errorf("nginx config test failed, so every change was put back:\n%s", out)
	}
	if out, err := run("systemctl", "reload", "nginx"); err != nil {
		return fmt.Errorf("config is valid but the reload failed: %s", out)
	}
	if err := writeAtomic(ServiceUnit, []byte(serviceUnitBody)); err != nil {
		return err
	}
	if err := writeAtomic(PathUnit, []byte(pathUnitBody)); err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(StagedFile), 0o700)
	if out, err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemd reload failed: %s", out)
	}
	if out, err := run("systemctl", "enable", "--now", filepath.Base(PathUnit)); err != nil {
		return fmt.Errorf("could not start the HTTPowl helper: %s", out)
	}
	if exists(StagedFile) { // blocks waiting from before: apply them now
		_ = ApplyStaged()
	}
	return nil
}

// Undo removes the helper, the include lines and both files, tests and reloads.
func Undo() error {
	if exists(PathUnit) {
		_, _ = run("systemctl", "disable", "--now", filepath.Base(PathUnit))
		_ = os.Remove(PathUnit)
		_ = os.Remove(ServiceUnit)
		_, _ = run("systemctl", "daemon-reload")
	}
	_ = os.Remove(StagedFile)
	_ = os.Remove(StatusFile)
	type change struct {
		path     string
		old, new []byte
	}
	var changes []change
	for _, f := range vhostFiles() {
		real, err := filepath.EvalSymlinks(f)
		if err != nil {
			continue
		}
		old, err := os.ReadFile(real)
		if err != nil || !bytes.Contains(old, []byte(includeDir)) {
			continue
		}
		changes = append(changes, change{real, old, []byte(removeIncludes(string(old)))})
	}
	for _, c := range changes {
		if err := writeAtomic(c.path, c.new); err != nil {
			return err
		}
	}
	mapOld, _ := os.ReadFile(MapFile)
	snipOld, _ := os.ReadFile(Snippet)
	_ = os.Remove(MapFile)
	_ = os.Remove(Snippet)
	if out, err := run("nginx", "-t"); err != nil {
		for _, c := range changes {
			_ = writeAtomic(c.path, c.old)
		}
		if mapOld != nil {
			_ = writeAtomic(MapFile, mapOld)
		}
		if snipOld != nil {
			_ = writeAtomic(Snippet, snipOld)
		}
		return fmt.Errorf("nginx config test failed after removing HTTPowl's lines, so they were put back:\n%s", out)
	}
	if out, err := run("systemctl", "reload", "nginx"); err != nil {
		return fmt.Errorf("reload failed: %s", out)
	}
	return nil
}

var serverOpen = regexp.MustCompile(`^\s*server\s*\{\s*(#.*)?$`)

// insertIncludes adds the include line after every top-level `server {` line
// that doesn't have it yet. missed is true when a server block is opened in a
// form we don't edit (e.g. `{` on the next line, or several statements on one line).
func insertIncludes(src string) (out string, added int, missed bool) {
	lines := strings.SplitAfter(src, "\n")
	var b strings.Builder
	depth := 0
	for i, line := range lines {
		code := stripComment(line)
		b.WriteString(line)
		if depth == 0 {
			t := strings.TrimSpace(code)
			if serverOpen.MatchString(strings.TrimRight(line, "\r\n")) {
				if !(i+1 < len(lines) && strings.Contains(lines[i+1], includeDir)) {
					if !strings.HasSuffix(line, "\n") {
						b.WriteString("\n")
					}
					b.WriteString(indentOf(line) + "    " + includeDir + "\n")
					added++
				}
			} else if t == "server" || strings.HasPrefix(t, "server{") || (strings.HasPrefix(t, "server ") && strings.Contains(t, "{")) {
				missed = true
			}
		}
		depth += strings.Count(code, "{") - strings.Count(code, "}")
		if depth < 0 {
			depth = 0
		}
	}
	return b.String(), added, missed
}

func removeIncludes(src string) string {
	lines := strings.SplitAfter(src, "\n")
	var b strings.Builder
	for _, l := range lines {
		if strings.TrimSpace(l) == includeDir {
			continue
		}
		b.WriteString(l)
	}
	return b.String()
}

// stripComment drops a # comment, ignoring # inside quotes.
func stripComment(line string) string {
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q != 0 && c == '\\':
			i++
		case q != 0 && c == q:
			q = 0
		case q == 0 && (c == '"' || c == '\''):
			q = c
		case q == 0 && c == '#':
			return line[:i]
		}
	}
	return line
}

func indentOf(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

func vhostFiles() []string {
	a, _ := filepath.Glob("/etc/nginx/sites-enabled/*")
	c, _ := filepath.Glob("/etc/nginx/conf.d/*.conf")
	var out []string
	for _, f := range append(a, c...) {
		if strings.HasPrefix(filepath.Base(f), "httpowl-") {
			continue
		}
		out = append(out, f)
	}
	return out
}

func writeAtomic(path string, b []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".httpowl-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func lastLine(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	last := s
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			last = t
		}
	}
	return last
}
