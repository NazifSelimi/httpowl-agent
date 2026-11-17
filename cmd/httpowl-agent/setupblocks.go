package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/NazifSelimi/httpowl-agent/internal/siteblock"
)

// setupBlocks: httpowl-agent setup-blocks [--check] [--yes] [--undo]
// Lets nginx refuse a visitor for one website only, after asking.
func setupBlocks(args []string) int {
	fs := flag.NewFlagSet("setup-blocks", flag.ExitOnError)
	check := fs.Bool("check", false, "only report whether it is set up (exit 3 = not yet)")
	yes := fs.Bool("yes", false, "don't ask (the person already agreed)")
	undo := fs.Bool("undo", false, "remove HTTPowl's per-website blocks again")
	_ = fs.Parse(args)

	if *check {
		if siteblock.Ready() {
			return exitOK
		}
		return exitNeeded
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "please run as root: sudo httpowl-agent setup-blocks")
		return exitFailed
	}
	if *undo {
		if err := siteblock.Undo(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitFailed
		}
		fmt.Println("Per-website blocks removed. Blocks on those websites no longer apply.")
		return exitOK
	}
	plan, err := siteblock.MakePlan()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitFailed
	}
	if plan.Already {
		fmt.Println("Already set up.")
		return exitOK
	}
	if len(plan.Files) == 0 {
		fmt.Fprintln(os.Stderr, "No nginx server blocks found to set up.")
		for _, f := range plan.Missed {
			fmt.Fprintln(os.Stderr, "  "+f)
		}
		return exitFailed
	}
	fmt.Println(plan.Describe())
	if !*yes && !ask("\nSet it up now? [y/N] ") {
		fmt.Println("Skipped. Nothing changed.")
		return exitOK
	}
	if err := plan.Apply(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitFailed
	}
	fmt.Println("Done. Blocks you add on a single website now apply only to that website.")
	return exitOK
}
