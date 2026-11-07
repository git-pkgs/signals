package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWorkflowFileSignalsRecordsPackageProvenance(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: push
jobs:
  npm-flag:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
  npm-environment:
    runs-on: ubuntu-latest
    env:
      NPM_CONFIG_PROVENANCE: true
    steps:
      - run: pnpm publish
  npm-inline:
    runs-on: ubuntu-latest
    steps:
      - run: env NPM_CONFIG_PROVENANCE=true yarn npm publish
  pypi-action:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@v1
  pypi-uv:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: uv publish dist/*
  pypi-password:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@v1
        with:
          password: ${{ secrets.PYPI_TOKEN }}
  pypi-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    env:
      UV_PUBLISH_TOKEN: ${{ secrets.PYPI_TOKEN }}
    steps:
      - run: uv publish dist/*
  pypi-inline-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: UV_PUBLISH_TOKEN=${{ secrets.PYPI_TOKEN }} uv publish dist/*
  pypi-token-option:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: uv publish --token ${{ secrets.PYPI_TOKEN }} dist/*
  pypi-short-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: uv publish -t ${{ secrets.PYPI_TOKEN }} dist/*
  pypi-attached-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: uv publish -t${{ secrets.PYPI_TOKEN }} dist/*
  pypi-disabled:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: uv publish --trusted-publishing never dist/*
  no-oidc:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@v1
  disabled:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance=false
`))
	if err != nil {
		t.Fatal(err)
	}

	want := []Signal{
		{Check: checkPackageProvenance, Kind: packageProvenanceNPMFlag, Name: "npm-flag", Value: packagingNameNPM, Path: testWorkflowPath},
		{Check: checkPackageProvenance, Kind: packageProvenanceNPMEnv, Name: "npm-environment", Value: "pnpm", Path: testWorkflowPath},
		{Check: checkPackageProvenance, Kind: packageProvenanceNPMEnv, Name: "npm-inline", Value: "yarn", Path: testWorkflowPath},
		{Check: checkPackageProvenance, Kind: packageProvenancePyPITrusted, Name: "pypi-action", Value: pypiPublishAction, Path: testWorkflowPath},
		{Check: checkPackageProvenance, Kind: packageProvenancePyPITrusted, Name: "pypi-uv", Value: "uv", Path: testWorkflowPath},
	}
	for _, signal := range want {
		if !hasWorkflowSignal(signals, signal) {
			t.Errorf("signal missing: %#v\ngot: %#v", signal, signals)
		}
	}
	if got := countCheckSignals(signals, checkPackageProvenance); got != len(want) {
		t.Fatalf("Package-Provenance signals = %d, want %d: %#v", got, len(want), signals)
	}
}

func TestWorkflowPackageProvenanceUsesEffectiveEnvironment(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: push
env:
  NPM_CONFIG_PROVENANCE: true
jobs:
  disabled:
    runs-on: ubuntu-latest
    env:
      NPM_CONFIG_PROVENANCE: false
    steps:
      - run: npm publish
  inline-disabled:
    runs-on: ubuntu-latest
    steps:
      - run: NPM_CONFIG_PROVENANCE=false npm publish
  flag-disabled:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance=false
  no-provenance:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --no-provenance
  last-flag-disabled:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance --provenance=false
  last-inline-disabled:
    runs-on: ubuntu-latest
    steps:
      - run: NPM_CONFIG_PROVENANCE=true NPM_CONFIG_PROVENANCE=false npm publish
  inherited:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
`))
	if err != nil {
		t.Fatal(err)
	}

	want := Signal{
		Check: checkPackageProvenance,
		Kind:  packageProvenanceNPMEnv,
		Name:  "inherited",
		Value: packagingNameNPM,
		Path:  testWorkflowPath,
	}
	if !hasWorkflowSignal(signals, want) {
		t.Fatalf("signal missing: %#v\ngot: %#v", want, signals)
	}
	if got := countCheckSignals(signals, checkPackageProvenance); got != 1 {
		t.Fatalf("Package-Provenance signals = %d, want 1: %#v", got, signals)
	}
}

func TestWorkflowPackageProvenanceAcrossHistory(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, testWorkflowPath, `on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Publish with provenance")

	writeFile(t, repo, testWorkflowPath, `on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance=false
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Disable publish provenance")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, expected := range []string{
		"+ Package-Provenance/npm-flag publish at .github/workflows/ci.yml = npm",
		"- Package-Provenance/npm-flag publish at .github/workflows/ci.yml = npm",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detector errors:\n%s", stderr.String())
	}
}

func countCheckSignals(signals []Signal, check string) int {
	count := 0
	for _, signal := range signals {
		if signal.Check == check {
			count++
		}
	}
	return count
}
