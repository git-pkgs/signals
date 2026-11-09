package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testStateSummaryCommand = "summary"
	testStateDiffCommand    = "diff"
	testStateJSONFlag       = "--json"
	testStateRefFlag        = "--ref"
	testStateMainRef        = "main"
)

func TestSummaryOutputsRevisionState(t *testing.T) {
	repo, initial, current := stateOutputRepository(t)

	var stdout, stderr bytes.Buffer
	if err := run([]string{testStateSummaryCommand, testStateJSONFlag, testStateRefFlag, testStateMainRef, repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run summary: %v\nstderr:\n%s", err, stderr.String())
	}
	var record stateSummaryRecord
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("decode summary: %v\n%s", err, stdout.String())
	}
	if record.Type != "summary" || record.Revision != testStateMainRef || record.Commit != current {
		t.Errorf("summary metadata = %#v", record)
	}
	if record.SignalCount != len(record.Signals) || record.CheckCount == 0 {
		t.Errorf("summary counts = %d signals, %d checks; signals = %d", record.SignalCount, record.CheckCount, len(record.Signals))
	}
	if !containsJSONLSignal(record.Signals, checkSecurityPolicy, "SECURITY.md") {
		t.Errorf("security policy missing from summary: %#v", record.Signals)
	}
	if !containsJSONLSignal(record.Signals, checkArtifactSigning, testGoReleaserPath) {
		t.Errorf("artifact signing missing from summary: %#v", record.Signals)
	}
	if !containsEvent(record.Events, checkSignedCommit, "openpgp", "") {
		t.Errorf("signed commit event missing from summary: %#v", record.Events)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected summary errors:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{testStateSummaryCommand, testStateRefFlag, initial, repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run text summary: %v\nstderr:\n%s", err, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "Security signals for") ||
		!strings.Contains(output, "Revision:    "+initial) ||
		strings.Contains(output, "Security-Policy") {
		t.Errorf("text summary:\n%s", output)
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{testStateSummaryCommand, "--markdown", testStateRefFlag, "HEAD", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run Markdown summary: %v\nstderr:\n%s", err, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "# Security signals for") ||
		!strings.Contains(output, "| Security-Policy |") ||
		!strings.Contains(output, "Sign current &#124; state") {
		t.Errorf("Markdown summary:\n%s", output)
	}
}

func TestDiffOutputsDirectStateChanges(t *testing.T) {
	repo, initial, current := stateOutputRepository(t)

	var stdout, stderr bytes.Buffer
	if err := run([]string{testStateDiffCommand, testStateJSONFlag, initial, current, repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run diff: %v\nstderr:\n%s", err, stderr.String())
	}
	var record stateDiffRecord
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatalf("decode diff: %v\n%s", err, stdout.String())
	}
	if record.Type != "diff" || record.From.Commit != initial || record.To.Commit != current {
		t.Errorf("diff metadata = %#v", record)
	}
	foundPolicy := false
	for _, change := range record.Changes {
		if change.Change == changeName('+') && change.Check == checkSecurityPolicy && change.Path == "SECURITY.md" {
			foundPolicy = true
		}
		if change.Check == checkSignedCommit {
			t.Errorf("commit event included in state diff: %#v", change)
		}
	}
	if !foundPolicy {
		t.Errorf("security policy change missing: %#v", record.Changes)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected diff errors:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{testStateDiffCommand, "--human", initial, current, repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run text diff: %v\nstderr:\n%s", err, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "Security signal diff for") ||
		!strings.Contains(output, "+ Security-Policy/") {
		t.Errorf("text diff:\n%s", output)
	}

	stdout.Reset()
	stderr.Reset()
	if err := run([]string{testStateDiffCommand, "--markdown", initial, current, repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run Markdown diff: %v\nstderr:\n%s", err, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "# Security signal diff for") ||
		!strings.Contains(output, "| added | Security-Policy |") {
		t.Errorf("Markdown diff:\n%s", output)
	}
}

func TestStateOutputValidatesArguments(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "summary formats", args: []string{testStateSummaryCommand, "--human", testStateJSONFlag}, want: "choose only one"},
		{name: "summary repositories", args: []string{testStateSummaryCommand, "one", "two"}, want: "usage: signals summary"},
		{name: "diff refs", args: []string{testStateDiffCommand, "main"}, want: "usage: signals diff"},
		{name: "diff repositories", args: []string{testStateDiffCommand, "one", "two", "three", "four"}, want: "usage: signals diff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(test.args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func stateOutputRepository(t *testing.T) (string, string, string) {
	t.Helper()
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", testStateMainRef)
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T00:00:00Z", "commit", "-m", "Initial commit")
	initial := gitOutput(t, repo, "rev-parse", "HEAD")

	writeFile(t, repo, "SECURITY.md", "Report issues to security@example.com.\n")
	writeFile(t, repo, testGoReleaserPath, "version: 2\nsigns:\n  - artifacts: checksum\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-02-01T00:00:00Z", "commit", "-m", "Add policy | review")
	addSignedCommit(t, repo, "2024-03-01T00:00:00Z", "Sign current | state")
	current := gitOutput(t, repo, "rev-parse", "HEAD")
	return repo, initial, current
}
