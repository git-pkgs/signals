package main

import (
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
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
`))
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
			Value: "read",
			Path:  testWorkflowPath,
			Line:  4,
		},
		{
			Check: checkTokenPermissions,
			Kind:  permissionKindTopLevel,
			Name:  "issues",
			Value: "write",
			Path:  testWorkflowPath,
			Line:  5,
		},
		{
			Check: checkTokenPermissions,
			Kind:  permissionKindJobLevel,
			Name:  "contents (Build)",
			Value: "write",
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
`))
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

func TestWorkflowSignalsForChangesUsesBlobCache(t *testing.T) {
	cache := make(map[workflowCacheKey][]Signal)
	changes := []githistory.Change{{Path: testWorkflowPath, NewOID: "1234"}}
	tree := fstest.MapFS{testWorkflowPath: {Data: []byte(`on: push
permissions: read-all
jobs: {}
`)}}

	first, paths, err := workflowSignalsForChanges(tree, changes, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(paths) != 1 {
		t.Fatalf("signals = %#v, paths = %#v", first, paths)
	}

	second, _, err := workflowSignalsForChanges(fstest.MapFS{}, changes, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		t.Fatalf("cached signals = %#v, want %#v", second, first)
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

func countWorkflowSignals(signals []Signal, check, kind string) int {
	count := 0
	for _, signal := range signals {
		if signal.Check == check && signal.Kind == kind {
			count++
		}
	}
	return count
}
