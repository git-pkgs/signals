package main

import (
	"slices"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

const (
	testPermissionRead  = "read"
	testPermissionWrite = "write"
)

func TestWorkflowFileSignalsDetectsWorkflowSecurityPosture(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`name: Security checks
on: pull_request_target
permissions:
  contents: read
  issues: write
jobs:
  build:
    name: Build
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: echo "${{ contains(github.event.issue.body, 'safe') }}"
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`), nil)
	if err != nil {
		t.Fatal(err)
	}

	want := []Signal{
		{
			Check: checkDangerousWorkflow,
			Kind:  workflowKindUntrustedCheckout,
			Name:  "Build",
			Value: "${{ github.event.pull_request.head.sha }}",
			Path:  testWorkflowPath,
			Line:  13,
		},
		{
			Check: checkDangerousWorkflow,
			Kind:  workflowKindScriptInjection,
			Name:  "Build",
			Value: "github.event.pull_request.title",
			Path:  testWorkflowPath,
			Line:  16,
		},
		{
			Check: checkTokenPermissions,
			Kind:  permissionKindTopLevel,
			Name:  "contents",
			Value: testPermissionRead,
			Path:  testWorkflowPath,
			Line:  4,
		},
		{
			Check: checkTokenPermissions,
			Kind:  permissionKindTopLevel,
			Name:  "issues",
			Value: testPermissionWrite,
			Path:  testWorkflowPath,
			Line:  5,
		},
		{
			Check: checkTokenPermissions,
			Kind:  permissionKindJobLevel,
			Name:  "contents (Build)",
			Value: testPermissionWrite,
			Path:  testWorkflowPath,
			Line:  10,
		},
		{
			Check: checkTokenPermissions,
			Kind:  permissionKindJobLevel,
			Name:  "lint",
			Value: "undeclared",
			Path:  testWorkflowPath,
			Line:  18,
		},
	}
	for _, signal := range want {
		if !hasWorkflowSignal(signals, signal) {
			t.Errorf("signal missing: %#v\ngot: %#v", signal, signals)
		}
	}
	if got := countWorkflowSignals(signals, checkDangerousWorkflow, workflowKindScriptInjection); got != 1 {
		t.Fatalf("script injection signals = %d, want 1: %#v", got, signals)
	}
}

func TestWorkflowFileSignalsDetectsUntrustedCheckoutForms(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: pull_request_target
jobs:
  merge-ref:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.number }}/merge
  fork:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.head_ref }}
  base:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.repository }}
          ref: ${{ github.head_ref }}
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []Signal{
		{
			Check: checkDangerousWorkflow,
			Kind:  workflowKindUntrustedCheckout,
			Name:  "merge-ref",
			Value: "refs/pull/${{ github.event.number }}/merge",
			Path:  testWorkflowPath,
			Line:  6,
		},
		{
			Check: checkDangerousWorkflow,
			Kind:  workflowKindUntrustedCheckout,
			Name:  "fork",
			Value: "${{ github.head_ref }}",
			Path:  testWorkflowPath,
			Line:  12,
		},
	} {
		if !hasWorkflowSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	if got := countWorkflowSignals(signals, checkDangerousWorkflow, workflowKindUntrustedCheckout); got != 2 {
		t.Fatalf("untrusted checkout signals = %d, want 2: %#v", got, signals)
	}
}

func TestWorkflowPathRequiresDirectChild(t *testing.T) {
	tests := map[string]bool{
		".github/workflows/ci.yml":        true,
		".github/workflows/release.yaml":  true,
		".github/workflows/nested/ci.yml": false,
		".github/workflows/README.md":     false,
		"workflows/ci.yml":                false,
	}
	for path, want := range tests {
		if got := isWorkflowPath(path); got != want {
			t.Errorf("isWorkflowPath(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestRemoveWorkflowCheckSignalsKeepsNestedYAML(t *testing.T) {
	signals := make(map[string]Signal)
	direct := Signal{Check: checkSAST, Path: ".github/workflows/ci.yml"}
	nested := Signal{Check: checkSAST, Path: ".github/workflows/nested/config.yml"}
	addSignals(signals, []Signal{direct, nested})

	removeWorkflowCheckSignals(signals, checkSAST)

	if hasSignal(signals, direct) || !hasSignal(signals, nested) {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestUntrustedScriptExpressionsUsesActionlintExpressionSemantics(t *testing.T) {
	script := `
echo "${{ github.event.issue.title }}"
echo "${{ contains(github.event.issue.body, 'release') }}"
echo "${{ toJSON(github.event) }}"
echo "${{ github.repository }}"
`
	want := []string{"github.event.issue.title", "toJSON(github.event)"}
	got := untrustedScriptExpressions(script)
	if len(got) != len(want) {
		t.Fatalf("expressions = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("expressions = %#v, want %#v", got, want)
		}
	}
}

func TestWorkflowFileSignalsDetectsSASTActions(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`name: Static analysis
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
      - uses: semgrep/semgrep-action@v1
`), nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, wanted := range []Signal{
		{
			Check: checkSAST,
			Kind:  signalKindTool,
			Name:  "CodeQL",
			Path:  testWorkflowPath,
			Line:  7,
		},
		{
			Check: checkSAST,
			Kind:  signalKindTool,
			Name:  "Semgrep",
			Path:  testWorkflowPath,
			Line:  8,
		},
	} {
		if !hasWorkflowSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestWorkflowFileSignalsDetectsArtifactProvenanceActions(t *testing.T) {
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`name: Release
on: push
jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest-build-provenance@v3
      - uses: actions/attest@v4
      - uses: actions/checkout@v4
`), nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, wanted := range []Signal{
		{
			Check: checkArtifactProvenance,
			Kind:  "slsa-generator",
			Name:  "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
			Path:  testWorkflowPath,
		},
		{
			Check: checkArtifactProvenance,
			Kind:  "attestation-action",
			Name:  "actions/attest-build-provenance",
			Path:  testWorkflowPath,
		},
		{
			Check: checkArtifactProvenance,
			Kind:  "attestation-action",
			Name:  "actions/attest",
			Path:  testWorkflowPath,
		},
	} {
		if !hasWorkflowSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	if got := countWorkflowSignals(signals, checkArtifactProvenance, "attestation-action"); got != 2 {
		t.Errorf("attestation signals = %d, want 2: %#v", got, signals)
	}
}

func TestWorkflowSignalsForChangesUsesBlobCache(t *testing.T) {
	cache := make(map[workflowCacheKey][]Signal)
	changes := []githistory.Change{{Path: testWorkflowPath, NewOID: "1234"}}
	tree := fstest.MapFS{testWorkflowPath: {Data: []byte(`on: push
permissions: read-all
jobs: {}
`)}}

	first, paths, err := workflowSignalsForChanges(tree, changes, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(paths) != 1 {
		t.Fatalf("signals = %#v, paths = %#v", first, paths)
	}

	second, _, err := workflowSignalsForChanges(fstest.MapFS{}, changes, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(second, first) {
		t.Fatalf("cached signals = %#v, want %#v", second, first)
	}

	current := emptyCommitState()
	addSignals(current.signals, first)
	detectors := &localDetectors{workflowCache: cache}
	stats := &scanStats{detectors: map[string]*detectorStats{detectorWorkflows: {}}}
	detectors.runWorkflows(
		fstest.MapFS{},
		[]githistory.Change{{Path: testWorkflowPath, OldOID: "1234"}},
		true,
		false,
		&current,
		stats,
	)
	for _, signal := range current.signals {
		if signal.Path == testWorkflowPath {
			t.Fatalf("deleted workflow signal remains: %#v", signal)
		}
	}
}

func TestWorkflowFileSignalsDetectsShellDataFlow(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`name: Install
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fsSL https://downloads.example/install.sh | bash
          npm ci
      - shell: pwsh
        run: Invoke-WebRequest https://ignored.example/tool
      - run: |-
          cargo update
  windows:
    runs-on: windows-latest
    steps:
      - run: curl -fsSL https://windows.example/install.sh | bash
      - shell: bash
        run: curl -fsSL https://bash.example/install.sh | bash
`), analyzer)
	if err != nil {
		t.Fatal(err)
	}

	for _, wanted := range []Signal{
		{
			Check: checkShellDependency,
			Kind:  shellKindDownloadAndRun,
			Name:  testDownloadHost,
			Value: shellStateUnverified,
			Path:  testWorkflowPath,
			Line:  8,
		},
		{
			Check: checkShellDependency,
			Kind:  shellKindPackageCommand,
			Name:  testNPMManager,
			Value: shellOperationInstall + ":frozen",
			Path:  testWorkflowPath,
			Line:  9,
		},
		{
			Check: checkShellDependency,
			Kind:  shellKindPackageCommand,
			Name:  "cargo",
			Value: shellOperationUpdate,
			Path:  testWorkflowPath,
			Line:  13,
		},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	if containsShellSignalName(signals, "ignored.example") {
		t.Fatalf("PowerShell run produced shell signal: %#v", signals)
	}
	if containsShellSignalName(signals, "windows.example") {
		t.Fatalf("default Windows shell produced shell signal: %#v", signals)
	}
	if !containsShellSignalName(signals, "bash.example") {
		t.Fatalf("explicit Bash step did not produce shell signal: %#v", signals)
	}
}

func TestWorkflowFileSignalsUsesRunDefaults(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: push
defaults:
  run:
    shell: pwsh
jobs:
  inherited:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://ignored.example/install.sh | bash
  overridden:
    runs-on: ubuntu-latest
    defaults:
      run:
        shell: bash
    steps:
      - run: curl -fsSL https://bash.example/install.sh | bash
`), analyzer)
	if err != nil {
		t.Fatal(err)
	}
	if containsShellSignalName(signals, "ignored.example") {
		t.Fatalf("workflow PowerShell default produced shell signal: %#v", signals)
	}
	if !containsShellSignalName(signals, "bash.example") {
		t.Fatalf("job Bash default did not produce shell signal: %#v", signals)
	}
}

func TestWorkflowFileSignalsSanitizesExpressionsForShellParsing(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals, err := workflowFileSignals(testWorkflowPath, []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ format('keep }} inside', github.ref) }}"
          curl -o "$tmp" -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://downloads.example/tool
`), analyzer)
	if err != nil {
		t.Fatal(err)
	}
	wanted := Signal{
		Check: checkShellDependency,
		Kind:  shellKindDownload,
		Name:  testDownloadHost,
		Value: shellStateUnverified,
		Path:  testWorkflowPath,
		Line:  8,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("workflow download signal missing: %#v\ngot: %#v", wanted, signals)
	}
	if containsShellSignalName(signals, "dynamic") {
		t.Fatalf("dynamic workflow download emitted with concrete URL: %#v", signals)
	}
}

func TestRunWorkflowsKeepsManifestProvenanceOnFullScan(t *testing.T) {
	manifest := Signal{
		Check: checkPackageProvenance,
		Kind:  packagingNameNPM,
		Name:  testPackageName,
		Path:  "package.json",
	}
	workflow := Signal{
		Check: checkPackageProvenance,
		Kind:  packageProvenanceNPMFlag,
		Name:  "publish",
		Path:  testWorkflowPath,
	}
	current := emptyCommitState()
	addSignals(current.signals, []Signal{manifest, workflow})
	detectors := &localDetectors{workflowCache: make(map[workflowCacheKey][]Signal)}
	stats := &scanStats{detectors: map[string]*detectorStats{detectorWorkflows: {}}}

	detectors.runWorkflows(fstest.MapFS{}, nil, true, true, &current, stats)

	if !hasSignal(current.signals, manifest) {
		t.Fatalf("manifest provenance was removed: %#v", current.signals)
	}
	if hasSignal(current.signals, workflow) {
		t.Fatalf("workflow provenance remains: %#v", current.signals)
	}
}

func hasWorkflowSignal(signals []Signal, wanted Signal) bool {
	for _, signal := range signals {
		if signal == wanted {
			return true
		}
	}
	return false
}

func containsShellSignalName(signals []Signal, name string) bool {
	for _, signal := range signals {
		if signal.Check == checkShellDependency && signal.Name == name {
			return true
		}
	}
	return false
}

func countWorkflowSignals(signals []Signal, check, kind string) int {
	count := 0
	for _, signal := range signals {
		if signal.Check == check && signal.Kind == kind {
			count++
		}
	}
	return count
}
