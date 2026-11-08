package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

const (
	testRootGitignore   = ".gitignore"
	testNestedGitignore = "services/api/.gitignore"
)

func TestSensitiveIgnoreSignalsDescribeEffectivePatterns(t *testing.T) {
	fsys := fstest.MapFS{
		testRootGitignore: {
			Data: []byte("*.log\n.env*\n*.tfstate\n[[:bogus:]]\n"),
		},
		testNestedGitignore: {
			Data: []byte("credentials.*\n!credentials.example\n"),
		},
		"testdata/project/.gitignore": {
			Data: []byte("*.key\n"),
		},
	}

	signals, err := sensitiveIgnoreSignals(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []Signal{
		{Check: checkSensitiveIgnore, Kind: "environment", Name: ".env", Value: ".env*", Path: testRootGitignore, Line: 2},
		{Check: checkSensitiveIgnore, Kind: "state", Name: "terraform.tfstate", Value: "*.tfstate", Path: testRootGitignore, Line: 3},
		{Check: checkSensitiveIgnore, Kind: "credential", Name: "services/api/credentials.json", Value: "credentials.*", Path: testNestedGitignore, Line: 1},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signals missing %#v:\n%#v", wanted, signals)
		}
	}
	for _, signal := range signals {
		if strings.HasPrefix(signal.Path, "testdata/") || signal.Name == "*.log" {
			t.Fatalf("unwanted ignore signal: %#v", signal)
		}
	}
	var invalid int
	for _, signal := range signals {
		if signal.Check == checkSensitiveIgnore && signal.Kind == "invalid-pattern" &&
			signal.Path == testRootGitignore && signal.Line == 4 {
			invalid++
		}
	}
	if invalid != 1 {
		t.Errorf("invalid pattern signals = %d, want 1: %#v", invalid, signals)
	}
}

func TestSensitiveIgnoresAffectedOnlyByProjectIgnoreFiles(t *testing.T) {
	tests := []struct {
		name   string
		change githistory.Change
		want   bool
	}{
		{name: "root", change: githistory.Change{Path: testRootGitignore}, want: true},
		{name: "nested", change: githistory.Change{Path: testNestedGitignore}, want: true},
		{name: "fixture", change: githistory.Change{Path: "testdata/project/.gitignore"}},
		{name: "other", change: githistory.Change{Path: ".dockerignore"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sensitiveIgnoresAffected([]githistory.Change{test.change}); got != test.want {
				t.Errorf("sensitiveIgnoresAffected = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSensitiveIgnoreSignalsBoundFileSize(t *testing.T) {
	fsys := fstest.MapFS{
		testRootGitignore: {Data: make([]byte, maxSensitiveIgnoreFileSize+1)},
	}
	signals, err := sensitiveIgnoreSignals(fsys)
	if err != nil {
		t.Fatal(err)
	}
	wanted := Signal{
		Check: checkSensitiveIgnore,
		Kind:  "coverage",
		Name:  "oversized-ignore-file",
		Value: "1048577",
		Path:  testRootGitignore,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("signals missing %#v: %#v", wanted, signals)
	}
}

func TestLogTracksSensitiveIgnorePolicy(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, testRootGitignore, ".env\n*.tfstate\n")
	gitRun(t, repo, "add", testRootGitignore)
	gitRun(t, repo, "commit", "-m", "Ignore local environment and state")

	writeFile(t, repo, testRootGitignore, ".env\n*.key\n")
	gitRun(t, repo, "add", ".gitignore")
	gitRun(t, repo, "commit", "-m", "Ignore private keys instead of state")

	if err := os.Remove(filepath.Join(repo, testRootGitignore)); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Remove ignore policy")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	output := stdout.String()
	for signal, counts := range map[string][2]int{
		"Sensitive-Ignore/environment .env":        {1, 1},
		"Sensitive-Ignore/state terraform.tfstate": {1, 1},
		"Sensitive-Ignore/private-key private.key": {1, 1},
	} {
		if got := strings.Count(output, "+ "+signal); got != counts[0] {
			t.Errorf("%s additions = %d, want %d:\n%s", signal, got, counts[0], output)
		}
		if got := strings.Count(output, "- "+signal); got != counts[1] {
			t.Errorf("%s removals = %d, want %d:\n%s", signal, got, counts[1], output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}
