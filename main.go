package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "signals:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: signals log [options] [repo]")
	}

	switch args[0] {
	case "log":
		return runLog(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runLog(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("log", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ref := flags.String("ref", "HEAD", "revision to walk")
	since := flags.String("since", "", "exclude this revision and its ancestors")
	after := flags.String("after", "", "include commits on or after YYYY-MM-DD")
	before := flags.String("before", "", "include commits before YYYY-MM-DD")
	workers := flags.Int("workers", 1, "concurrent history readers")
	progress := flags.Int("progress", 0, "report progress every N commits")
	stats := flags.Bool("stats", false, "report detector and blob-cache statistics")
	jsonl := flags.Bool("jsonl", false, "write one JSON object per changed commit")
	snapshots := flags.Bool("snapshots", false, "emit signal snapshots at both date boundaries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateDate("after", *after); err != nil {
		return err
	}
	if err := validateDate("before", *before); err != nil {
		return err
	}
	if *after != "" && *before != "" && *after >= *before {
		return errors.New("after date must be earlier than before date")
	}
	if *snapshots && (*after == "" || *before == "") {
		return errors.New("snapshots require both --after and --before")
	}
	if *workers < 1 {
		return errors.New("workers must be positive")
	}
	if *progress < 0 {
		return errors.New("progress must be non-negative")
	}
	if flags.NArg() > 1 {
		return errors.New("usage: signals log [options] [repo]")
	}
	repo := "."
	if flags.NArg() == 1 {
		repo = flags.Arg(0)
	}

	return logSignals(repo, LogOptions{
		Ref:       *ref,
		Since:     *since,
		After:     *after,
		Before:    *before,
		Workers:   *workers,
		Progress:  *progress,
		Stats:     *stats,
		JSONL:     *jsonl,
		Snapshots: *snapshots,
	}, stdout, stderr)
}

func validateDate(name, value string) error {
	if value == "" {
		return nil
	}
	if _, err := time.Parse(time.DateOnly, value); err != nil {
		return fmt.Errorf("invalid --%s date %q: use YYYY-MM-DD", name, value)
	}
	return nil
}
