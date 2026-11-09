package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLogWritesSignedReleaseAndGittufEvents(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T00:00:00Z", "commit", "-m", "Initial commit")
	initial := gitOutput(t, repo, "rev-parse", "HEAD")
	addSignedTag(t, repo, initial, "v0.9.0", "2024-01-02T00:00:00Z")
	gitRun(t, repo, "tag", "-a", "v0.8.0", initial, "-m", "Unsigned release")

	addSignedCommit(t, repo, "2024-02-01T00:00:00Z", "Signed release commit")
	gitRun(t, repo, "tag", "v1.0.0")

	writeFile(t, repo, "current.txt", "current\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-03-01T00:00:00Z", "commit", "-m", "Current tip")
	tip := gitOutput(t, repo, "rev-parse", "HEAD")
	tree := gitOutput(t, repo, "rev-parse", "HEAD^{tree}")
	policy := gitOutput(t, repo, "commit-tree", tree, "-m", "gittuf policy")
	gitRun(t, repo, "update-ref", gittufPolicyRef, policy)
	attestations := gitOutput(t, repo, "commit-tree", tree, "-m", "gittuf attestations")
	gitRun(t, repo, "update-ref", gittufAttestRef, attestations)
	rslRoot := gitOutput(t, repo, "commit-tree", tree, "-m", "RSL Reference Entry\n\nref: refs/heads/main\ntargetID: "+initial)
	rslTip := gitOutput(t, repo, "commit-tree", tree, "-p", rslRoot, "-m", "RSL Reference Entry\n\nref: refs/heads/main\ntargetID: "+tip)
	gitRun(t, repo, "update-ref", gittufRSLRef, rslTip)

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testJSONLFlag, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	records := decodeEventRecords(t, stdout.Bytes())
	initialRecord := findEventRecord(t, records, "Initial commit")
	if !containsEvent(initialRecord.Events, checkSignedRelease, "tag-openpgp", "v0.9.0") {
		t.Errorf("signed tag event missing: %#v", initialRecord.Events)
	}
	if containsEvent(initialRecord.Events, checkSignedRelease, "tag-openpgp", "v0.8.0") {
		t.Errorf("unsigned tag reported as signed: %#v", initialRecord.Events)
	}

	signedCommit := findEventRecord(t, records, "Signed release commit")
	if !containsEvent(signedCommit.Events, checkSignedRelease, "commit-openpgp", "v1.0.0") {
		t.Errorf("tagged signed commit event missing: %#v", signedCommit.Events)
	}
	if !containsEvent(signedCommit.Events, checkSignedCommit, "openpgp", "") {
		t.Errorf("signed commit event missing: %#v", signedCommit.Events)
	}

	current := findEventRecord(t, records, "Current tip")
	for _, expected := range []struct {
		kind string
		name string
	}{
		{kind: "policy-ref", name: gittufPolicyRef},
		{kind: "attestations-ref", name: gittufAttestRef},
		{kind: "rsl-ref", name: gittufRSLRef},
	} {
		if !containsEvent(current.Events, checkGittuf, expected.kind, expected.name) {
			t.Errorf("Gittuf %s event missing: %#v", expected.kind, current.Events)
		}
	}
	if got := eventValue(current.Events, checkGittuf, "rsl-entry-count", ""); got != "2" {
		t.Errorf("RSL entry count = %q, want 2", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	missingParent := strings.Repeat("1", 40)
	rslContent := fmt.Sprintf(`tree %s
parent %s
author RSL Test <rsl@example.com> 0 +0000
committer RSL Test <rsl@example.com> 0 +0000

RSL Reference Entry
`, tree, missingParent)
	cmd := exec.Command("git", "hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(rslContent)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("write shallow RSL commit: %v\n%s", err, output)
	}
	gitRun(t, repo, "update-ref", gittufRSLRef, strings.TrimSpace(string(output)))
	if err := run([]string{
		testLogCommand, "--ref", "v0.8.0", testJSONLFlag, testWorkersFlag, "1", repo,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run log at annotated tag: %v\nstderr:\n%s", err, stderr.String())
	}
	initialRecord = findEventRecord(t, decodeEventRecords(t, stdout.Bytes()), "Initial commit")
	if !containsEvent(initialRecord.Events, checkGittuf, "policy-ref", gittufPolicyRef) {
		t.Errorf("Gittuf event missing at annotated tag commit: %#v", initialRecord.Events)
	}
	if got := eventValue(initialRecord.Events, checkGittuf, "rsl-entry-count", ""); got != "1" {
		t.Errorf("shallow RSL entry count = %q, want 1", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected annotated-tag detection errors:\n%s", stderr.String())
	}
}

func addSignedTag(t *testing.T, path, target, name, date string) {
	t.Helper()
	when, err := time.Parse(time.RFC3339, date)
	if err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`object %s
type commit
tag %s
tagger Release Tagger <release@example.com> %d +0000

Release %s
-----BEGIN PGP SIGNATURE-----

ZmFrZQ==
-----END PGP SIGNATURE-----
`, target, name, when.Unix(), name)
	cmd := exec.Command("git", "hash-object", "-t", "tag", "-w", "--stdin")
	cmd.Dir = path
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("write signed tag: %v\n%s", err, output)
	}
	gitRun(t, path, "update-ref", "refs/tags/"+name, strings.TrimSpace(string(output)))
}

func eventValue(events []jsonlSignal, check, kind, name string) string {
	for _, event := range events {
		if event.Check == check && event.Kind == kind && event.Name == name {
			return event.Value
		}
	}
	return ""
}
