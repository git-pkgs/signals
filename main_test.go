package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogDetectsSignalChangesAcrossHistory(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, ".github/dependabot.yml", "version: 2\nupdates: []\n")
	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	writeFile(t, repo, ".github/workflows/ci.yml", `name: CI
on: [push]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.issue.title }}"
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add security configuration")

	if err := os.Remove(filepath.Join(repo, "SECURITY.md")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-u")
	gitRun(t, repo, "commit", "-m", "Remove security policy")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"Add security configuration",
		"+ Dependency-Update-Tool/tool Dependabot at .github/dependabot.yml:1",
		"+ Dangerous-Workflow/scriptInjection",
		"+ Pinned-Dependencies/GitHubAction actions/checkout",
		"+ Security-Policy/policy at SECURITY.md:1",
		"+ Token-Permissions/topLevel",
		"Remove security policy",
		"- Security-Policy/policy at SECURITY.md:1",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing %q:\n%s", expected, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogComparesBranchCommitsWithTheirFirstParent(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2016-12-18T00:00:00Z", "commit", "-m", "Initial commit")

	gitRun(t, repo, "switch", "-c", "feature")
	writeFile(t, repo, "Dockerfile", "FROM ruby:3.4\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2016-12-18T00:01:00Z", "commit", "-m", "Add container")

	gitRun(t, repo, "switch", "main")
	writeFile(t, repo, "main.txt", "main branch\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2016-12-18T00:02:00Z", "commit", "-m", "Update main")
	gitRunAt(t, repo, "2016-12-18T00:03:00Z", "merge", "--no-ff", "feature", "-m", "Merge feature")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	const signal = "Pinned-Dependencies/containerImage ruby at Dockerfile:1 = unpinned"
	if count := strings.Count(stdout.String(), "+ "+signal); count != 1 {
		t.Fatalf("added signal count = %d, want 1:\n%s", count, stdout.String())
	}
	if strings.Contains(stdout.String(), "- "+signal) {
		t.Fatalf("branch traversal produced a false removal:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogWritesJSONL(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T12:00:00Z", "commit", "-m", "Initial commit")

	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-02-01T12:00:00Z", "commit", "-m", "Add security policy")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--jsonl", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("JSONL line count = %d, want 1:\n%s", len(lines), stdout.String())
	}
	var record jsonlRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("decode JSONL: %v\n%s", err, lines[0])
	}
	if len(record.Commit) != 40 {
		t.Errorf("commit length = %d, want 40", len(record.Commit))
	}
	if record.Type != "change" {
		t.Errorf("type = %q", record.Type)
	}
	if record.Author.Name != "Signals Test" || record.Author.Email != "signals@example.com" {
		t.Errorf("author = %#v", record.Author)
	}
	if got := record.AuthoredAt.Format(time.RFC3339); got != "2024-02-01T12:00:00Z" {
		t.Errorf("authored_at = %q", got)
	}
	if record.Subject != "Add security policy" {
		t.Errorf("subject = %q", record.Subject)
	}
	if !containsJSONLChange(record.Changes, "added", checkSecurityPolicy, "SECURITY.md") {
		t.Errorf("security policy change missing: %#v", record.Changes)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogWritesBoundarySnapshots(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T12:00:00Z", "commit", "-m", "Initial commit")

	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-15T12:00:00Z", "commit", "-m", "Add policy before funding")

	if err := os.Remove(filepath.Join(repo, "SECURITY.md")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-u")
	gitRunAt(t, repo, "2024-02-15T12:00:00Z", "commit", "-m", "Remove policy after funding")

	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"log",
		"--jsonl",
		"--snapshots",
		"--after", "2024-02-01",
		"--before", "2024-03-01",
		"--workers", "1",
		repo,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("JSONL line count = %d, want 3:\n%s", len(lines), stdout.String())
	}
	var start, end jsonlSnapshotRecord
	var change jsonlRecord
	if err := json.Unmarshal([]byte(lines[0]), &start); err != nil {
		t.Fatalf("decode start snapshot: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &change); err != nil {
		t.Fatalf("decode change: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &end); err != nil {
		t.Fatalf("decode end snapshot: %v", err)
	}

	if start.Type != "snapshot" || start.Boundary != "start" || start.Date != "2024-02-01" {
		t.Errorf("start snapshot metadata = %#v", start)
	}
	if start.Author == nil || start.Author.Name != "Signals Test" || start.Author.Email != "signals@example.com" {
		t.Errorf("start author = %#v", start.Author)
	}
	if !containsJSONLSignal(start.Signals, checkSecurityPolicy, "SECURITY.md") {
		t.Errorf("start snapshot missing security policy: %#v", start.Signals)
	}
	if change.Type != "change" || change.Subject != "Remove policy after funding" {
		t.Errorf("change record = %#v", change)
	}
	if end.Type != "snapshot" || end.Boundary != "end" || end.Date != "2024-03-01" {
		t.Errorf("end snapshot metadata = %#v", end)
	}
	if containsJSONLSignal(end.Signals, checkSecurityPolicy, "SECURITY.md") {
		t.Errorf("end snapshot still contains removed security policy: %#v", end.Signals)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogFiltersOutputByAuthorDateWithoutDiscardingEarlierState(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T12:00:00Z", "commit", "-m", "Initial commit")

	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-15T12:00:00Z", "commit", "-m", "Add policy before funding")

	if err := os.Remove(filepath.Join(repo, "SECURITY.md")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-u")
	gitRunAt(t, repo, "2024-02-01T12:00:00Z", "commit", "-m", "Remove policy after funding")

	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-03-01T12:00:00Z", "commit", "-m", "Restore policy at upper bound")

	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"log",
		"--after", "2024-02-01",
		"--before", "2024-03-01",
		"--workers", "1",
		repo,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "Remove policy after funding") {
		t.Fatalf("in-range removal missing:\n%s", output)
	}
	if !strings.Contains(output, "- Security-Policy/policy at SECURITY.md:1") {
		t.Fatalf("removal did not use state before the date range:\n%s", output)
	}
	for _, excluded := range []string{"Add policy before funding", "Restore policy at upper bound"} {
		if strings.Contains(output, excluded) {
			t.Errorf("output contains excluded commit %q:\n%s", excluded, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestRunRejectsInvalidDates(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "after format",
			args: []string{"log", "--after", "2024/02/01"},
			want: `invalid --after date "2024/02/01": use YYYY-MM-DD`,
		},
		{
			name: "before format",
			args: []string{"log", "--before", "tomorrow"},
			want: `invalid --before date "tomorrow": use YYYY-MM-DD`,
		},
		{
			name: "empty range",
			args: []string{"log", "--after", "2024-02-01", "--before", "2024-02-01"},
			want: "after date must be earlier than before date",
		},
		{
			name: "snapshots without range",
			args: []string{"log", "--snapshots"},
			want: "snapshots require both --after and --before",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := run(test.args, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || err.Error() != test.want {
				t.Fatalf("got %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunRejectsInvalidWorkers(t *testing.T) {
	err := run([]string{"log", "--workers", "0"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "workers must be positive" {
		t.Fatalf("got %v", err)
	}
}

func containsJSONLChange(changes []jsonlChange, change, check, path string) bool {
	for _, candidate := range changes {
		if candidate.Change == change && candidate.Check == check && candidate.Path == path {
			return true
		}
	}
	return false
}

func containsJSONLSignal(signals []jsonlSignal, check, path string) bool {
	for _, signal := range signals {
		if signal.Check == check && signal.Path == path {
			return true
		}
	}
	return false
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func gitRunAt(t *testing.T, dir, date string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(fmt.Errorf("write %s: %w", name, err))
	}
}
