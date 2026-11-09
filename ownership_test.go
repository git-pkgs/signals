package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testCodeownersPath      = ".gitlab/CODEOWNERS"
	testMaintainersPath     = "MAINTAINERS.md"
	testOwnershipLogCommand = "log"
)

func TestRepositoryOwnershipSignals(t *testing.T) {
	data := []byte(`# project owners
* @example/core security@example.com
/docs/ @example/docs
escaped\#name @example/core # retained pattern, ignored comment
[Backend][2] @example/backend # @example/comment-owner
`)
	signals := repositorySignals(t, testCodeownersPath, data)
	summary := findOwnershipSignal(t, signals, ownershipKindCodeowners, "summary")
	if !strings.HasPrefix(summary.Value, "rules=3; owners=5; config=") {
		t.Fatalf("summary = %#v", summary)
	}
	for _, owner := range []string{
		"@example/backend",
		"@example/comment-owner",
		"@example/core",
		"@example/docs",
		"security@example.com",
	} {
		findOwnershipSignal(t, signals, ownershipKindOwner, owner)
	}

	for _, test := range []struct {
		path string
		kind string
	}{
		{path: testMaintainersPath, kind: ownershipKindMaintainers},
		{path: "docs/GOVERNANCE.md", kind: ownershipKindGovernance},
	} {
		data := []byte("project document\n")
		found := repositorySignals(t, test.path, data)
		signal := findOwnershipSignal(t, found, test.kind, "")
		if signal.Value != contentDigest(data) {
			t.Errorf("%s digest = %q, want %q", test.path, signal.Value, contentDigest(data))
		}
		changed := findOwnershipSignal(t, repositorySignals(t, test.path, []byte("updated document\n")), test.kind, "")
		if changed.Value == signal.Value {
			t.Errorf("%s digest did not change with content", test.path)
		}
	}
}

func TestRepositoryOwnershipSignalsUseGitHubComments(t *testing.T) {
	data := []byte("\\#not-a-pattern @example/ignored\nescaped\\#name @example/escaped\n* @example/actual # @example/comment\n")
	signals := repositorySignals(t, ".github/CODEOWNERS", data)
	summary := findOwnershipSignal(t, signals, ownershipKindCodeowners, "summary")
	if !strings.HasPrefix(summary.Value, "rules=2; owners=2; config=") {
		t.Fatalf("summary = %#v", summary)
	}
	findOwnershipSignal(t, signals, ownershipKindOwner, "@example/actual")
	findOwnershipSignal(t, signals, ownershipKindOwner, "@example/escaped")
	for _, ignored := range []string{"@example/ignored", "@example/comment"} {
		for _, signal := range signals {
			if signal.Check == checkRepositoryOwnership && signal.Kind == ownershipKindOwner && signal.Name == ignored {
				t.Errorf("GitHub comment owner was reported: %#v", signal)
			}
		}
	}
}

func TestRepositoryOwnershipSignalsSupportsLongRules(t *testing.T) {
	data := append(bytes.Repeat([]byte{'x'}, int(repositoryFileContentBytes)-len(" @example/owner")), []byte(" @example/owner")...)
	signals := repositorySignals(t, ".github/CODEOWNERS", data)
	summary := findOwnershipSignal(t, signals, ownershipKindCodeowners, "summary")
	if !strings.HasPrefix(summary.Value, "rules=1; owners=1; config=") {
		t.Fatalf("summary = %#v", summary)
	}
	findOwnershipSignal(t, signals, ownershipKindOwner, "@example/owner")
}

func TestRepositoryOwnershipSignalsReportTruncatedCodeowners(t *testing.T) {
	prefix := []byte("* @example/owner\n")
	data := append([]byte(nil), prefix...)
	data = append(data, bytes.Repeat([]byte{'x'}, codeownersContentBytes+1-len(prefix))...)
	signals := repositorySignals(t, ".github/CODEOWNERS", data)
	findOwnershipSignal(t, signals, ownershipKindOwner, "@example/owner")
	coverage := findOwnershipSignal(t, signals, ownershipKindCoverage, ownershipTruncatedName)
	want := fmt.Sprintf("bytes=%d; limit=%d", len(data), codeownersContentBytes)
	if coverage.Value != want {
		t.Fatalf("coverage value = %q, want %q", coverage.Value, want)
	}
}

func TestRepositoryOwnershipSignalsExcludeBundledDocuments(t *testing.T) {
	for _, filePath := range []string{
		"vendor/dependency/CODEOWNERS",
		"testdata/project/MAINTAINERS.md",
		"fixtures/repository/GOVERNANCE.md",
	} {
		if signals := repositorySignals(t, filePath, []byte("* @dependency/owners\n")); len(signals) != 0 {
			t.Errorf("%s signals = %#v", filePath, signals)
		}
	}
}

func TestLogTracksRepositoryOwnershipChanges(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, testCodeownersPath, "* @example/old\n")
	writeFile(t, repo, testMaintainersPath, "Old Maintainer <old@example.com>\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add ownership")

	writeFile(t, repo, testCodeownersPath, "* @example/new\n")
	writeFile(t, repo, testMaintainersPath, "New Maintainer <new@example.com>\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Change ownership")

	if err := os.Remove(filepath.Join(repo, testCodeownersPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo, testMaintainersPath)); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-u")
	gitRun(t, repo, "commit", "-m", "Remove ownership")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testOwnershipLogCommand, testJSONLFlag, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	var records []jsonlRecord
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var record jsonlRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode JSONL: %v\n%s", err, line)
		}
		records = append(records, record)
	}
	added := findJSONLRecord(t, records, "Add ownership")
	changed := findJSONLRecord(t, records, "Change ownership")
	removed := findJSONLRecord(t, records, "Remove ownership")
	assertOwnershipChange(t, added.Changes, "added", "@example/old")
	assertOwnershipChange(t, changed.Changes, "removed", "@example/old")
	assertOwnershipChange(t, changed.Changes, "added", "@example/new")
	assertOwnershipChange(t, removed.Changes, "removed", "@example/new")
	oldMaintainers := contentDigest([]byte("Old Maintainer <old@example.com>\n"))
	newMaintainers := contentDigest([]byte("New Maintainer <new@example.com>\n"))
	assertOwnershipDocumentChange(t, added.Changes, "added", oldMaintainers)
	assertOwnershipDocumentChange(t, changed.Changes, "removed", oldMaintainers)
	assertOwnershipDocumentChange(t, changed.Changes, "added", newMaintainers)
	assertOwnershipDocumentChange(t, removed.Changes, "removed", newMaintainers)
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func findOwnershipSignal(t *testing.T, signals []Signal, kind, name string) Signal {
	t.Helper()
	for _, signal := range signals {
		if signal.Check == checkRepositoryOwnership && signal.Kind == kind && signal.Name == name {
			return signal
		}
	}
	t.Fatalf("ownership signal kind=%q name=%q not found: %#v", kind, name, signals)
	return Signal{}
}

func assertOwnershipChange(t *testing.T, changes []jsonlChange, change, name string) {
	t.Helper()
	for _, candidate := range changes {
		if candidate.Change == change && candidate.Check == checkRepositoryOwnership &&
			candidate.Kind == ownershipKindOwner && candidate.Name == name && candidate.Path == testCodeownersPath {
			return
		}
	}
	t.Errorf("ownership change=%q name=%q not found: %#v", change, name, changes)
}

func assertOwnershipDocumentChange(t *testing.T, changes []jsonlChange, change, value string) {
	t.Helper()
	for _, candidate := range changes {
		if candidate.Change == change && candidate.Check == checkRepositoryOwnership &&
			candidate.Kind == ownershipKindMaintainers && candidate.Value == value &&
			candidate.Path == testMaintainersPath {
			return
		}
	}
	t.Errorf("maintainers change=%q value=%q not found: %#v", change, value, changes)
}
