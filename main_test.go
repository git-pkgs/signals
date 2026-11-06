package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	githistory "github.com/git-pkgs/history"
	"github.com/go-git/go-git/v6/plumbing"
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
	writeFile(t, repo, testWorkflowPath, `name: CI
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

func TestLogDetectsDependencyUpdateConfigChanges(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# Example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, ".github/dependabot.yml", `version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Configure weekly updates")

	writeFile(t, repo, ".github/dependabot.yml", `version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: cron
      cronjob: "0 8 * * 1"
    cooldown:
      default-days: 7
`)
	writeFile(t, repo, "renovate.json5", `{
  enabledManagers: ['gomod'],
  extends: ['config:recommended'],
}`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Configure dependency update policy")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"+ Dependency-Update-Config/Dependabot npm at .github/dependabot.yml = directory=/; schedule=weekly",
		"- Dependency-Update-Config/Dependabot npm at .github/dependabot.yml = directory=/; schedule=weekly",
		"+ Dependency-Update-Config/Dependabot npm at .github/dependabot.yml = directory=/; schedule=cron; cronjob=0 8 * * 1; cooldown=default-days:7",
		"+ Dependency-Update-Config/Renovate gomod at renovate.json5:1 = enabled",
		"+ Dependency-Update-Tool/tool Renovate at renovate.json5:1",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing %q:\n%s", expected, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogDetectsRenovateInPackageJSON(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, packageJSONPath, `{"name":"example"}`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, packageJSONPath, `{
  "name": "example",
  "renovate": "config:recommended"
}`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Configure Renovate")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"+ Dependency-Update-Config/Renovate config at package.json:1 = extends=config:recommended",
		"+ Dependency-Update-Tool/tool Renovate at package.json:1",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing %q:\n%s", expected, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogDetectsPackagePostureChanges(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# Example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, packageJSONPath, `{
  "name": "example",
  "dependencies": {
    "exact": "1.2.3",
    "ranged": "^2.0.0"
  }
}`)
	writeFile(t, repo, "package-lock.json", `{
  "name": "example",
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"exact": "1.2.3", "ranged": "^2.0.0"}},
    "node_modules/exact": {"version": "1.2.3", "integrity": "sha512-example"},
    "node_modules/ranged": {"version": "2.1.0", "integrity": "sha512-example"}
  }
}`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add npm dependencies")

	writeFile(t, repo, packageJSONPath, `{
  "name": "example",
  "dependencies": {
    "exact": "1.2.4",
    "ranged": "^2.0.0"
  }
}`)
	if err := os.Remove(filepath.Join(repo, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Update exact dependency without lockfile")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"+ Package-File/manifest npm at package.json",
		"+ Package-File/lockfile npm at package-lock.json",
		"+ Dependency-Pin/npm pkg:npm/exact at package.json = 1.2.3",
		"- Dependency-Pin/npm pkg:npm/exact at package.json = 1.2.3",
		"+ Dependency-Pin/npm pkg:npm/exact at package.json = 1.2.4",
		"- Package-File/lockfile npm at package-lock.json",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing %q:\n%s", expected, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogDetectsPackageManagerChanges(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# Example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, "apps/tool/example.nimble", "version = \"0.1.0\"\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add Nimble project")

	writeFile(t, repo, "apps/tool/nimble.lock", "{}\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Lock Nimble dependencies")

	if err := os.RemoveAll(filepath.Join(repo, "apps/tool")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Remove Nimble project")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"+ Package-Manager/nimble nimble at apps/tool",
		"+ Package-File/lockfile nimble at apps/tool/nimble.lock",
		"- Package-Manager/nimble nimble at apps/tool",
		"- Package-File/lockfile nimble at apps/tool/nimble.lock",
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

func TestLogUsesLanguagesAndRolesForFuzzing(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "main.go", "package main\nfunc main() {}\n")
	writeFile(t, repo, "vendor/dependency/fuzz_test.go", "package dependency\nfunc FuzzVendor(f *testing.F) {}\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add project and vendored fuzz target")

	writeFile(t, repo, "fuzz_test.go", "package main\nfunc FuzzProject(f *testing.F) {}\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add project fuzz target")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "Add project fuzz target") || !strings.Contains(output, "+ Fuzzing/fuzzer") {
		t.Fatalf("project fuzz target missing:\n%s", output)
	}
	if strings.Contains(output, "vendor/dependency/fuzz_test.go") {
		t.Fatalf("vendored fuzz target was reported:\n%s", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogDetectsLocalToolingSecretsAndREUSEAcrossHistory(t *testing.T) {
	const prefixBeyondCommonScanLimit = 64*1024 + 1

	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	const token = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	writeFile(t, repo, testWorkflowPath, "name: CI\non: push\njobs: {}\n")
	writeFile(t, repo, ".pre-commit-config.yaml", "repos: []\n")
	writeFile(t, repo, testSemgrepConfigPath, "rules: []\n")
	writeFile(t, repo, ".sops.yaml", "creation_rules: []\n")
	writeFile(t, repo, "Makefile", "all:\n\t@true\n")
	writeFile(t, repo, "config.yml", "token: "+token+"\n")
	writeFile(t, repo, "licensed.txt", strings.Repeat("x", prefixBeyondCommonScanLimit)+
		"\nSPDX-FileCopyrightText: 2026 Signals Test\nSPDX-License-Identifier: MIT\n")
	writeFile(t, repo, "main.c", "int main(void) { return 0; }\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add local security evidence")

	for _, name := range []string{
		testWorkflowPath,
		".pre-commit-config.yaml",
		testSemgrepConfigPath,
		".sops.yaml",
		"config.yml",
	} {
		if err := os.Remove(filepath.Join(repo, name)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, repo, "licensed.txt", "Licensing pending.\n")
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Remove local security evidence")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--jsonl", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), token) {
		t.Fatal("JSONL output contains the detected secret")
	}

	var records []jsonlRecord
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var record jsonlRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode JSONL: %v\n%s", err, line)
		}
		records = append(records, record)
	}
	added := findJSONLRecord(t, records, "Add local security evidence")
	removed := findJSONLRecord(t, records, "Remove local security evidence")

	expectedAdditions := []jsonlChange{
		{Change: "added", Check: checkCI, Kind: "GitHub Actions", Path: ".github/workflows/"},
		{Change: "added", Check: checkPreCommit, Kind: "pre-commit", Path: ".pre-commit-config.yaml"},
		{Change: "added", Check: checkSecretsManagement, Kind: "SOPS", Path: ".sops.yaml"},
		{Change: "added", Check: checkSecurityTool, Kind: testSecurityScanKind, Name: testSemgrepName, Path: testSemgrepConfigPath},
		{Change: "added", Check: checkBuild, Kind: "Make"},
		{Change: "added", Check: checkSecret, Kind: "github-pat", Value: "[redacted]", Path: "config.yml", Line: 1},
		{Change: "added", Check: checkREUSE, Kind: "declaration", Value: "MIT", Path: "licensed.txt"},
	}
	for _, expected := range expectedAdditions {
		if !containsExactJSONLChange(added.Changes, expected) {
			t.Errorf("added record missing %#v:\n%s", expected, stdout.String())
		}
	}
	for _, expected := range expectedAdditions {
		if expected.Check == checkBuild {
			continue
		}
		expected.Change = "removed"
		if !containsExactJSONLChange(removed.Changes, expected) {
			t.Errorf("removed record missing %#v:\n%s", expected, stdout.String())
		}
	}
	for _, change := range removed.Changes {
		if change.Check == checkBuild {
			t.Errorf("unchanged build signal was removed: %#v\n%s", change, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLocalDetectorsDoNotRetainBlobContents(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	const token = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	writeFile(t, repo, "oversized.data", token+"\n"+strings.Repeat("x", maxSecretBlobSize))
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add oversized blob")

	for i := range 6 {
		writeFile(t, repo, fmt.Sprintf("history/%02d.data", i), fmt.Sprintf("revision %d\n", i))
		gitRun(t, repo, "add", ".")
		gitRun(t, repo, "commit", "-m", fmt.Sprintf("Add history blob %d", i))
	}

	historyRepo, err := githistory.Open(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := historyRepo.Close(); err != nil {
			t.Error(err)
		}
	})
	local, err := newLocalDetectors(t.Context(), historyRepo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := local.Close(); err != nil {
			t.Error(err)
		}
	})
	cache := newBlobCache(historyRepo.Repository())
	stats := newScanStats(cache)
	state := emptyCommitState()
	first := true
	err = historyRepo.WalkCommits(githistory.CommitOptions{Workers: 1, Merges: true}, func(commit githistory.Commit) error {
		current, err := local.detect(t.Context(), commit.Object, state, commit.Changes, first, false, stats)
		if err != nil {
			return err
		}
		state = current
		first = false
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.data) != 0 {
		t.Fatalf("local detectors retained %d blob contents", len(cache.data))
	}
	for _, signal := range state.signals {
		if signal.Check == checkSecret {
			t.Fatalf("oversized blob produced a secret signal: %#v", signal)
		}
	}
}

func TestCommitStateStoreReleasesFirstParentBranches(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "root.txt", "root\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Root")
	root := plumbing.NewHash(gitCommandOutput(t, repo, "rev-parse", "HEAD"))
	gitRun(t, repo, "branch", "feature")

	writeFile(t, repo, "main.txt", "main\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Main")
	main := plumbing.NewHash(gitCommandOutput(t, repo, "rev-parse", "HEAD"))

	gitRun(t, repo, "switch", "feature")
	writeFile(t, repo, "feature.txt", "feature\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Feature")
	feature := plumbing.NewHash(gitCommandOutput(t, repo, "rev-parse", "HEAD"))
	gitRun(t, repo, "switch", "main")
	gitRun(t, repo, "merge", "--no-ff", "feature", "-m", "Merge feature")

	historyRepo, err := githistory.Open(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := historyRepo.Close(); err != nil {
			t.Error(err)
		}
	})
	walk, states, err := planCommitWalk(historyRepo, LogOptions{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if states.remaining[root] != 2 || states.remaining[main] != 1 || states.remaining[feature] != 0 {
		t.Fatalf("unexpected first-parent child counts: %#v", states.remaining)
	}
	peak := 0
	err = historyRepo.WalkCommits(walk, func(commit githistory.Commit) error {
		if len(commit.Object.ParentHashes) > 0 {
			parent := commit.Object.ParentHashes[0]
			if _, ok := states.get(parent); !ok {
				return fmt.Errorf("parent %s was released before %s", parent, commit.Object.Hash)
			}
			states.release(parent)
		}
		state := emptyCommitState()
		state.reuseActive = true
		state.reuseFiles[commit.Object.Hash.String()] = reuseFile{covered: true}
		states.retain(commit.Object.Hash, state)
		peak = max(peak, len(states.states))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(states.states) != 0 {
		t.Fatalf("retained %d commit states after the walk", len(states.states))
	}
	if peak > 2 {
		t.Fatalf("peak retained states = %d, want at most 2", peak)
	}
}

func TestReaderContainsAnyAcrossChunks(t *testing.T) {
	marker := reuseMetadataMarkers[0]
	prefix := strings.Repeat("x", reuseMarkerReadSize-len(marker)/2)
	matched, err := readerContainsAny(strings.NewReader(prefix+string(marker)), reuseMetadataMarkers[:])
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("marker spanning read chunks was not detected")
	}
}

func TestLogScansEveryDetectedLanguage(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "main.go", "package main\nfunc main() {}\n")
	writeFile(t, repo, "fuzz_test.go", "package main\nfunc FuzzProject(f *testing.F) {}\n")
	writeFile(t, repo, "web/app.js", strings.Repeat("const value = 1;\n", 500))
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add project")

	if err := os.Remove(filepath.Join(repo, "web/app.js")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Remove JavaScript")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "Add project") || !strings.Contains(output, "+ Fuzzing/fuzzer") {
		t.Fatalf("Go fuzz target missing from mixed-language project:\n%s", output)
	}
	if strings.Contains(output, "Remove JavaScript") {
		t.Fatalf("removing another language changed the fuzzing signal:\n%s", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogTracksBriefLanguagesAcrossSymlinkTransitions(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# Example\n")
	writeFile(t, repo, testRubyPath, "puts 'hello'\n")
	writeFile(t, repo, ".overcommit.yml", "PreCommit: {}\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add Ruby project")

	if err := os.Remove(filepath.Join(repo, testRubyPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("README.md", filepath.Join(repo, testRubyPath)); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Replace Ruby file with symlink")

	if err := os.Remove(filepath.Join(repo, testRubyPath)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, repo, testRubyPath, "puts 'hello again'\n")
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Restore Ruby file")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{
		"Add Ruby project",
		"Replace Ruby file with symlink",
		"- Pre-Commit/Overcommit at .overcommit.yml",
		"Restore Ruby file",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing %q:\n%s", expected, output)
		}
	}
	if additions := strings.Count(output, "+ Pre-Commit/Overcommit at .overcommit.yml"); additions != 2 {
		t.Errorf("Overcommit additions = %d, want 2:\n%s", additions, output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func TestLogRebuildsLanguagesAtShallowBoundary(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "old.c", "int old_value;\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add C source")

	if err := os.Remove(filepath.Join(repo, "old.c")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, repo, "main.go", "package main\n")
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Replace C with Go")
	boundary := gitCommandOutput(t, repo, "rev-parse", "HEAD")

	writeFile(t, repo, "new.c", "int new_value;\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add C again")
	writeFile(t, repo, ".git/shallow", boundary+"\n")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", "--stats", "--workers", "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	var fuzzingStats string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(line, "signals: Fuzzing") {
			fuzzingStats = line
			break
		}
	}
	if !strings.Contains(fuzzingStats, "runs=3 full=3 partial=0") {
		t.Fatalf("Fuzzing stats = %q, want three full scans\nstderr:\n%s", fuzzingStats, stderr.String())
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

func TestLogFiltersOutputByCommitterDateWithoutDiscardingEarlierState(t *testing.T) {
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
	gitRunWithDates(
		t, repo, "2024-01-20T12:00:00Z", "2024-02-01T12:00:00Z",
		"commit", "-m", "Remove policy after funding",
	)

	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	gitRun(t, repo, "add", ".")
	gitRunWithDates(
		t, repo, "2024-02-15T12:00:00Z", "2024-03-01T12:00:00Z",
		"commit", "-m", "Restore policy at upper bound",
	)

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

func TestRunPropagatesWriterErrors(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")
	writeFile(t, repo, "SECURITY.md", "Report vulnerabilities to security@example.com.\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T12:00:00Z", "commit", "-m", "Add security policy")

	tests := []struct {
		name   string
		args   []string
		stdout io.Writer
		stderr io.Writer
	}{
		{name: "version", args: []string{"version"}, stdout: failingWriter{}, stderr: io.Discard},
		{name: "text", args: []string{"log", repo}, stdout: failingWriter{}, stderr: io.Discard},
		{name: "JSONL", args: []string{"log", "--jsonl", repo}, stdout: failingWriter{}, stderr: io.Discard},
		{name: "progress", args: []string{"log", "--progress", "1", repo}, stdout: io.Discard, stderr: failingWriter{}},
		{name: "stats", args: []string{"log", "--stats", repo}, stdout: io.Discard, stderr: failingWriter{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := run(test.args, test.stdout, test.stderr)
			if !errors.Is(err, errWriteFailed) {
				t.Fatalf("got %v, want %v", err, errWriteFailed)
			}
		})
	}
}

var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
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

func findJSONLRecord(t *testing.T, records []jsonlRecord, subject string) jsonlRecord {
	t.Helper()
	for _, record := range records {
		if record.Subject == subject {
			return record
		}
	}
	t.Fatalf("record for %q not found: %#v", subject, records)
	return jsonlRecord{}
}

func containsExactJSONLChange(changes []jsonlChange, expected jsonlChange) bool {
	for _, change := range changes {
		if change == expected {
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

func gitCommandOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
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

func gitRunWithDates(t *testing.T, dir, authorDate, committerDate string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+authorDate, "GIT_COMMITTER_DATE="+committerDate)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func gitRunAtAs(
	t *testing.T,
	dir, date, authorName, authorEmail, committerName, committerEmail string,
	args ...string,
) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE="+date,
		"GIT_COMMITTER_DATE="+date,
		"GIT_AUTHOR_NAME="+authorName,
		"GIT_AUTHOR_EMAIL="+authorEmail,
		"GIT_COMMITTER_NAME="+committerName,
		"GIT_COMMITTER_EMAIL="+committerEmail,
	)
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
