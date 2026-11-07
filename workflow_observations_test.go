package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWorkflowFileSignalsRecordsWorkflowObservations(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`name: Release
on: workflow_call
cache-mode: read
permissions:
  contents: read
jobs:
  build:
    name: Build packages
    permissions:
      packages: write
    cache-mode: write-only
    timeout-minutes: 30
    runs-on: ubuntu-latest
    steps:
      - run: |
          python -m build
          python -m twine upload dist/*
      - uses: docker/build-push-action@v6
        with:
          push: true
  call:
    permissions:
      contents: read
    uses: ./.github/workflows/publish.yml
`))
	if err != nil {
		t.Fatal(err)
	}

	want := []Signal{
		{Check: checkCacheMode, Kind: workflowObservationTopLevel, Value: testPermissionRead, Path: testWorkflowPath, Line: 3},
		{Check: checkCacheMode, Kind: workflowObservationJobLevel, Name: "Build packages", Value: "write-only", Path: testWorkflowPath, Line: 11},
		{Check: checkJobTimeout, Kind: workflowObservationJobLevel, Name: "Build packages", Value: "30", Path: testWorkflowPath, Line: 12},
		{Check: checkPackaging, Kind: packagingKindPackage, Name: "Python", Path: testWorkflowPath, Line: 15},
		{Check: checkPackaging, Kind: packagingKindPublish, Name: packagingNamePyPI, Path: testWorkflowPath, Line: 16},
		{Check: checkPackaging, Kind: packagingKindPublish, Name: packagingNameContainer, Value: "docker/build-push-action", Path: testWorkflowPath, Line: 18},
		{Check: checkTokenPermissions, Kind: permissionKindReusableTop, Name: "contents", Value: testPermissionRead, Path: testWorkflowPath, Line: 5},
		{Check: checkTokenPermissions, Kind: permissionKindReusableJob, Name: "packages (Build packages)", Value: testPermissionWrite, Path: testWorkflowPath, Line: 10},
		{Check: checkTokenPermissions, Kind: permissionKindReusableCall, Name: "contents (call)", Value: testPermissionRead, Path: testWorkflowPath, Line: 23},
	}
	for _, signal := range want {
		if !hasWorkflowSignal(signals, signal) {
			t.Errorf("signal missing: %#v\ngot: %#v", signal, signals)
		}
	}
}

func TestWorkflowFileSignalsRecordsTimeoutExpression(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: push
jobs:
  build:
    timeout-minutes: ${{ matrix.timeout }}
    strategy:
      matrix:
        timeout: [15]
    runs-on: ubuntu-latest
    steps:
      - run: npm pack && npm publish --//registry.npmjs.org/:_authToken=committed-secret
`))
	if err != nil {
		t.Fatal(err)
	}

	for _, wanted := range []Signal{
		{Check: checkJobTimeout, Kind: workflowObservationJobLevel, Name: buildName, Value: "expression:matrix.timeout", Path: testWorkflowPath, Line: 4},
		{Check: checkPackaging, Kind: packagingKindPackage, Name: packagingNameNPM, Path: testWorkflowPath, Line: 10},
		{Check: checkPackaging, Kind: packagingKindPublish, Name: packagingNameNPM, Path: testWorkflowPath, Line: 10},
	} {
		if !hasWorkflowSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	for _, signal := range signals {
		if strings.Contains(signal.Value, "committed-secret") {
			t.Fatalf("packaging signal copied command arguments: %#v", signal)
		}
	}
}

func TestWorkflowFileSignalsRecordsRunnerSelection(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: push
jobs:
  hosted:
    runs-on: ubuntu-latest
    steps: [{run: echo hosted}]
  self:
    name: Private runner
    runs-on: [self-hosted, X64, Linux]
    steps: [{run: echo private}]
  grouped:
    runs-on:
      group: secure-runners
      labels: ubuntu-24.04
    steps: [{run: echo grouped}]
  dynamic:
    runs-on: ${{ matrix.runner }}
    steps: [{run: echo dynamic}]
`))
	if err != nil {
		t.Fatal(err)
	}

	for _, wanted := range []Signal{
		{Check: checkRunnerSelection, Kind: runnerKindSelfHosted, Name: "Private runner", Value: "Linux,X64,self-hosted", Path: testWorkflowPath},
		{Check: checkRunnerSelection, Kind: runnerKindGroup, Name: "grouped", Value: "secure-runners", Path: testWorkflowPath},
		{Check: checkRunnerSelection, Kind: runnerKindDynamic, Name: "dynamic", Value: "expression:matrix.runner", Path: testWorkflowPath},
	} {
		if !hasWorkflowSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestPackagingCommandDistinguishesBuildFromPackage(t *testing.T) {
	tests := []struct {
		command string
		kind    string
		name    string
	}{
		{command: "cargo build"},
		{command: "npm run build"},
		{command: "cargo package", kind: packagingKindPackage, name: "cargo"},
		{command: "gem build example.gemspec", kind: packagingKindPackage, name: "RubyGems"},
		{command: "helm push chart.tgz oci://registry.example", kind: packagingKindPublish, name: "Helm"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			kind, name := packagingCommand(strings.Fields(test.command))
			if kind != test.kind || name != test.name {
				t.Fatalf("packagingCommand(%q) = %q, %q, want %q, %q", test.command, kind, name, test.kind, test.name)
			}
		})
	}
}

func TestWorkflowObservationsAcrossHistory(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, testWorkflowPath, `on: workflow_call
cache-mode: read
permissions: {}
jobs:
  release:
    timeout-minutes: 30
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: npm pack
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add reusable packaging workflow")

	writeFile(t, repo, testWorkflowPath, `on: workflow_call
cache-mode: write-only
permissions: {}
jobs:
  release:
    timeout-minutes: 20
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Publish the package")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, expected := range []string{
		"+ Cache-Mode/topLevel at .github/workflows/ci.yml:2 = read",
		"+ Job-Timeout/jobLevel release at .github/workflows/ci.yml:6 = 30",
		"+ Packaging/package npm at .github/workflows/ci.yml:9",
		"+ Runner-Selection/self-hosted release at .github/workflows/ci.yml = linux,self-hosted,x64",
		"+ Token-Permissions/reusableTopLevel at .github/workflows/ci.yml:3 = none",
		"+ Cache-Mode/topLevel at .github/workflows/ci.yml:2 = write-only",
		"- Cache-Mode/topLevel at .github/workflows/ci.yml:2 = read",
		"+ Packaging/publish npm at .github/workflows/ci.yml:9",
		"- Packaging/package npm at .github/workflows/ci.yml:9",
		"- Runner-Selection/self-hosted release at .github/workflows/ci.yml = linux,self-hosted,x64",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detector errors:\n%s", stderr.String())
	}
}
