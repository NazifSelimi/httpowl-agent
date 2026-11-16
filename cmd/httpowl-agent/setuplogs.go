package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/NazifSelimi/httpowl-agent/internal/agent/detect"
	"github.com/NazifSelimi/httpowl-agent/internal/setuplogs"
)

// Exit codes for `setup-logs --check` (used by the installer).
const (
	exitOK     = 0
	exitFailed = 1
	exitNeeded = 3 // a domain log would help and isn't set up yet
)

// setupLogs: httpowl-agent setup-logs [--check] [--yes] [--undo]
// Adds (or removes) the HTTPowl domain log for each detected web server, after asking.
func setupLogs(args []string) int {
	fs := flag.NewFlagSet("setup-logs", flag.ExitOnError)
	check := fs.Bool("check", false, "only report whether a domain log is needed (exit 3 = needed)")
	yes := fs.Bool("yes", false, "don't ask (the person already agreed)")
	undo := fs.Bool("undo", false, "remove the HTTPowl domain log again")
	_ = fs.Parse(args)

	var plans []*setuplogs.Server
	for _, name := range detect.Names(detect.Detect()) {
		plan, err := setuplogs.For(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			continue
		}
		if plan != nil {
			plans = append(plans, plan)
		}
	}

	if *check {
		for _, p := range plans {
			if !p.Installed() {
				return exitNeeded
			}
		}
		return exitOK
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "please run as root: sudo httpowl-agent setup-logs")
		return exitFailed
	}
	if len(plans) == 0 {
		fmt.Println("Nothing to do: your web server already logs the domain (or none was found).")
		return exitOK
	}

	status := exitOK
	for _, p := range plans {
		if *undo {
			if err := p.Undo(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				status = exitFailed
				continue
			}
			fmt.Printf("%s: HTTPowl domain log removed.\n", p.Name)
			continue
		}
		if p.Installed() {
			fmt.Printf("%s: already set up (%s).\n", p.Name, p.ConfFile)
			continue
		}
		fmt.Println(p.Describe())
		if !*yes && !ask("\nAdd it now? [y/N] ") {
			fmt.Println("Skipped. Nothing changed.")
			continue
		}
		if err := p.Apply(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			status = exitFailed
			continue
		}
		fmt.Printf("%s: done. Visits are now logged with their domain in %s.\n", p.Name, p.LogFile)
	}
	if status == exitOK && !*undo {
		fmt.Println("Restart the agent to read the new log: sudo systemctl restart httpowl-agent")
	}
	return status
}

// ask reads y/N from the terminal, even when stdin is a pipe (curl | sh).
func ask(prompt string) bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false // no terminal: never change anything without an answer
	}
	defer tty.Close()
	fmt.Print(prompt)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
