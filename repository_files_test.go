package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

const (
	testLicensePath        = "LICENSE"
	testMITLicenseID       = "MIT"
	testFuzzPath           = "fuzz_test.go"
	testFuzzerKind         = "fuzzer"
	testGoFuzzerName       = "GoBuiltInFuzzer"
	testJSONLFlag          = "--jsonl"
	testSecurityPolicyPath = ".github/SECURITY.md"
	testStatsFlag          = "--stats"
	testWorkersFlag        = "--workers"
)

const mitLicenseText = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

func TestRepositoryFileSignalsUsesGitPkgsParsers(t *testing.T) {
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, make([]byte, 64)...)
	binarySignals := repositorySignals(t, "bin/tool", elf)
	if !containsExactSignal(binarySignals, Signal{
		Check: checkBinaryArtifacts,
		Kind:  "artifact",
		Name:  "elf",
		Value: "application/x-elf",
		Path:  "bin/tool",
	}) {
		t.Fatalf("binary signals = %#v", binarySignals)
	}

	licenseSignals := repositorySignals(t, testLicensePath, []byte(mitLicenseText))
	if !containsExactSignal(licenseSignals, Signal{
		Check: checkLicense,
		Kind:  signalKindLicense,
		Name:  testMITLicenseID,
		Path:  testLicensePath,
	}) {
		t.Fatalf("license signals = %#v", licenseSignals)
	}

	noticeSignals := repositorySignals(t, "NOTICE", []byte("Third-party notices\n"))
	if !containsExactSignal(noticeSignals, Signal{
		Check: checkLicense,
		Kind:  signalKindNotice,
		Path:  "NOTICE",
	}) {
		t.Fatalf("notice signals = %#v", noticeSignals)
	}
	for _, signal := range noticeSignals {
		if signal.Kind == signalKindLicense {
			t.Fatalf("plain notice signals = %#v", noticeSignals)
		}
	}
	licensedNoticeSignals := repositorySignals(
		t,
		"docs/NOTICE",
		[]byte("Project notice\n\n"+mitLicenseText),
	)
	if !containsExactSignal(licensedNoticeSignals, Signal{
		Check: checkLicense,
		Kind:  signalKindLicense,
		Name:  testMITLicenseID,
		Path:  "docs/NOTICE",
	}) {
		t.Fatalf("licensed notice signals = %#v", licensedNoticeSignals)
	}

	sbomSignals := repositorySignals(t, "artifacts/inventory.json", []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}`))
	if !containsExactSignal(sbomSignals, Signal{
		Check: checkSBOM,
		Kind:  "document",
		Name:  "cyclonedx",
		Value: "1.6",
		Path:  "artifacts/inventory.json",
		Line:  1,
	}) {
		t.Fatalf("SBOM signals = %#v", sbomSignals)
	}

	policySignals := repositorySignals(t, testSecurityPolicyPath, []byte(
		"Report issues to security@example.com.\nSee https://example.com/security.\n"+
			"Read the [policy](https://example.com/security.).\n",
	))
	for _, wanted := range []Signal{
		{Check: checkSecurityPolicy, Kind: "policy", Path: testSecurityPolicyPath, Line: 1},
		{Check: checkSecurityPolicy, Kind: "email", Value: "security@example.com", Path: testSecurityPolicyPath, Line: 1},
		{Check: checkSecurityPolicy, Kind: "link", Value: "https://example.com/security", Path: testSecurityPolicyPath, Line: 2},
		{Check: checkSecurityPolicy, Kind: "link", Value: "https://example.com/security.", Path: testSecurityPolicyPath, Line: 3},
	} {
		if !containsExactSignal(policySignals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, policySignals)
		}
	}
}

func TestRepositoryFileSignalsReportsUnrecognizedSBOMCandidate(t *testing.T) {
	signals := repositorySignals(t, "bom.cdx.json", []byte(`{"name":"not an sbom"}`))
	wanted := Signal{
		Check: checkSBOM,
		Kind:  "candidate",
		Name:  "bom.cdx.json",
		Path:  "bom.cdx.json",
		Line:  1,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestRepositoryFileSignalsDoesNotTreatSourceNamesAsLegalEvidence(t *testing.T) {
	for _, filePath := range []string{"notice.go", "licenses/_spdx.py"} {
		if signals := repositorySignals(t, filePath, []byte("package example\n")); len(signals) != 0 {
			t.Errorf("%s signals = %#v", filePath, signals)
		}
	}
	if signals := repositorySignals(t, "src/pkg/LICENSE", []byte(mitLicenseText)); !containsExactSignal(signals, Signal{
		Check: checkLicense,
		Kind:  signalKindLicense,
		Name:  testMITLicenseID,
		Path:  "src/pkg/LICENSE",
	}) {
		t.Errorf("nested license signals = %#v", signals)
	}
}

func TestRepositoryFileSignalsDetectsFuzzersAndSASTConfig(t *testing.T) {
	tests := []struct {
		path string
		data string
		want Signal
	}{
		{
			path: testFuzzPath,
			data: "package example\nfunc FuzzProject(f *testing.F) {}\n",
			want: Signal{
				Check: checkFuzzing,
				Kind:  testFuzzerKind,
				Name:  testGoFuzzerName,
				Value: "func FuzzProject(f *testing.F)",
				Path:  testFuzzPath,
				Line:  2,
			},
		},
		{
			path: "multiline_fuzz_test.go",
			data: "package example\nfunc\nFuzzProject(f *testing.F) {}\n",
			want: Signal{
				Check: checkFuzzing,
				Kind:  testFuzzerKind,
				Name:  testGoFuzzerName,
				Value: "func\nFuzzProject(f *testing.F)",
				Path:  "multiline_fuzz_test.go",
				Line:  2,
			},
		},
		{
			path: ".clusterfuzzlite/Dockerfile",
			data: "FROM gcr.io/oss-fuzz-base/base-builder\n",
			want: Signal{
				Check: checkFuzzing,
				Kind:  testFuzzerKind,
				Name:  "ClusterFuzzLite",
				Path:  ".clusterfuzzlite/Dockerfile",
				Line:  1,
			},
		},
		{
			path: "java/pom.xml",
			data: "<properties>\n  <sonar.host.url>https://sonar.example</sonar.host.url>\n</properties>\n",
			want: Signal{
				Check: checkSAST,
				Kind:  signalKindTool,
				Name:  sastToolSonar,
				Value: "https://sonar.example",
				Path:  "java/pom.xml",
				Line:  2,
			},
		},
	}
	for _, test := range tests {
		if signals := repositorySignals(t, test.path, []byte(test.data)); !containsExactSignal(signals, test.want) {
			t.Errorf("%s signals = %#v, want %#v", test.path, signals, test.want)
		}
	}

	if signals := repositorySignals(t,
		"vendor/dependency/fuzz_test.go",
		[]byte("package dependency\nfunc FuzzVendor(f *testing.F) {}\n"),
	); len(signals) != 0 {
		t.Fatalf("vendored fuzzing signals = %#v", signals)
	}
}

func TestRepositoryFileSignalsForChangesUsesBlobCache(t *testing.T) {
	cache := make(map[repositoryFileCacheKey][]Signal)
	changes := []githistory.Change{{Path: testLicensePath, NewOID: "1234"}}
	tree := fstest.MapFS{testLicensePath: {Data: []byte(mitLicenseText)}}

	first, paths, err := repositoryFileSignalsForChanges(t.Context(), tree, changes, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(paths) != 1 {
		t.Fatalf("signals = %#v, paths = %#v", first, paths)
	}

	second, _, err := repositoryFileSignalsForChanges(t.Context(), fstest.MapFS{}, changes, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		t.Fatalf("cached signals = %#v, want %#v", second, first)
	}
}

func TestRepositoryFileSignalsForChangesSkipsDirectories(t *testing.T) {
	changes := []githistory.Change{{Path: testLicensePath, NewOID: "1234"}}
	tree := fstest.MapFS{testLicensePath: {Mode: fs.ModeDir}}

	signals, paths, err := repositoryFileSignalsForChanges(
		t.Context(),
		tree,
		changes,
		make(map[repositoryFileCacheKey][]Signal),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 || len(paths) != 1 || paths[0] != testLicensePath {
		t.Fatalf("signals = %#v, paths = %#v", signals, paths)
	}
}

func TestRepositoryFileFuzzingSelectionSkipsVendoredSources(t *testing.T) {
	if fuzzingFile("vendor/dependency/fuzz_test.go") {
		t.Fatal("vendored fuzz source selected")
	}
	if !fuzzingFile(testFuzzPath) {
		t.Fatal("project fuzz source not selected")
	}
}

func TestRepositoryFileFuzzingMatchCrossesReadBoundary(t *testing.T) {
	match := "func FuzzProject(f *testing.F)"
	data := bytes.Repeat([]byte{'x'}, repositoryFileScanBytes-len("func "))
	data = append(data, match...)
	signals := repositorySignals(t, testFuzzPath, data)
	wanted := Signal{
		Check: checkFuzzing,
		Kind:  testFuzzerKind,
		Name:  testGoFuzzerName,
		Value: match,
		Path:  testFuzzPath,
		Line:  1,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestReadRepositoryFileLimitsContent(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, int(repositoryFileContentBytes)+1)
	read, err := readRepositoryFile(
		fstest.MapFS{"large.txt": {Data: data}},
		"large.txt",
		repositoryFileContentBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != int(repositoryFileContentBytes) {
		t.Fatalf("read %d bytes, want %d", len(read), repositoryFileContentBytes)
	}
}

func TestLogDetectsRepositoryFileSignals(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# Example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, testLicensePath, mitLicenseText)
	writeFile(t, repo, "SECURITY.md", "Report issues to security@example.com.\n")
	writeFile(t, repo, "bom.json", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)
	writeFile(t, repo, "tool.wasm", string([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}))
	paddingLine := "// history padding\n"
	paddingLines := int(repositoryFileContentBytes)/len(paddingLine) + 1
	writeFile(t, repo, testFuzzPath,
		"package example\n"+strings.Repeat(paddingLine, paddingLines)+"func FuzzProject(f *testing.F) {}\n",
	)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add repository security evidence")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"log", testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, expected := range []string{
		"+ Binary-Artifacts/artifact wasm at tool.wasm = application/wasm",
		"+ License/license MIT at LICENSE",
		"+ SBOM/document cyclonedx at bom.json:1 = 1.6",
		"+ Security-Policy/policy at SECURITY.md:1",
		"+ Security-Policy/email at SECURITY.md:1 = security@example.com",
		fmt.Sprintf("+ Fuzzing/%s %s at %s:%d", testFuzzerKind, testGoFuzzerName, testFuzzPath, paddingLines+2),
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func repositorySignals(t *testing.T, filePath string, data []byte) []Signal {
	t.Helper()
	signals, err := repositoryFileSignalsFromFS(
		t.Context(),
		fstest.MapFS{filePath: {Data: data}},
		filePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signals
}

func containsExactSignal(signals []Signal, wanted Signal) bool {
	for _, signal := range signals {
		if signal == wanted {
			return true
		}
	}
	return false
}
