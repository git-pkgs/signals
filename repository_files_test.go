package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	githistory "github.com/git-pkgs/history"
)

const (
	testLicensePath        = "LICENSE"
	testMITLicenseID       = "MIT"
	testFuzzPath           = "fuzz_test.go"
	testFuzzerKind         = "fuzzer"
	testGoFuzzerName       = "GoBuiltInFuzzer"
	testJSONLFlag          = "--jsonl"
	testLogCommand         = "log"
	testPackageName        = "example"
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

func TestRepositoryFileSignalsDetectsCertificates(t *testing.T) {
	pemData, fingerprint := testCertificatePEM(t, 1)
	for _, filePath := range []string{"trust.pem", "renamed.bin"} {
		signals := repositorySignals(t, filePath, pemData)
		identity := findCertificateSignal(t, signals, "identity", fingerprint)
		if !strings.Contains(identity.Value, "subject=CN=Signals Test CA 1") ||
			!strings.Contains(identity.Value, "not-after=2030-01-01T00:00:00Z") ||
			!strings.Contains(identity.Value, "ca=true") {
			t.Fatalf("certificate identity = %#v", identity)
		}
		collection := findCertificateSignal(t, signals, "collection", "")
		if !strings.Contains(collection.Value, "format=pem") ||
			!strings.Contains(collection.Value, "certificates=1") {
			t.Fatalf("certificate collection = %#v", collection)
		}
	}

	if signals := repositorySignals(t, "testdata/trust.pem", pemData); len(signals) != 0 {
		t.Fatalf("fixture certificate signals = %#v", signals)
	}
}

func TestRepositoryFileSignalsEscapesCertificateControlCharacters(t *testing.T) {
	pemData, fingerprint := testCertificatePEMWithName(t, 4, "Signals Test\n- forged")
	identity := findCertificateSignal(t, repositorySignals(t, "trust.pem", pemData), "identity", fingerprint)
	if strings.Contains(identity.Value, "\n") {
		t.Fatalf("certificate identity contains a newline: %q", identity.Value)
	}
	if !strings.Contains(identity.Value, `subject="CN=Signals Test\n- forged"`) ||
		!strings.Contains(identity.Value, `issuer="CN=Signals Test\n- forged"`) {
		t.Fatalf("certificate identity = %#v", identity)
	}
}

func TestLogEscapesCertificateControlCharacters(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	pemData, _ := testCertificatePEMWithName(t, 5, "Signals Test\n- forged")
	if err := os.WriteFile(filepath.Join(repo, "trust.pem"), pemData, 0o644); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("roots\n- forged/trust.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(pemData); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "package.jar"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "trust.pem", "package.jar")
	gitRun(t, repo, "commit", "-m", "Add trust certificate")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	output := stdout.String()
	if strings.Contains(output, "\n- forged") {
		t.Fatalf("certificate identity created a report line:\n%s", output)
	}
	if !strings.Contains(output, `subject="CN=Signals Test\n- forged"`) {
		t.Fatalf("escaped certificate identity missing:\n%s", output)
	}
	if !strings.Contains(output, `location="package.jar!roots\n- forged/trust.pem#1"`) {
		t.Fatalf("escaped certificate location missing:\n%s", output)
	}
}

func TestRepositoryFileSignalsDetectsCertificateInsideArchive(t *testing.T) {
	pemData, fingerprint := testCertificatePEM(t, 2)
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("roots/trust.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(pemData); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	signals := repositorySignals(t, "package.jar", archive.Bytes())
	findCertificateSignal(t, signals, "identity", fingerprint)
	collection := findCertificateSignal(t, signals, "collection", "")
	if !strings.Contains(collection.Value, "location=package.jar!roots/trust.pem#1") {
		t.Fatalf("archive certificate collection = %#v", collection)
	}
}

func TestCertificateFileCandidateBoundsInputs(t *testing.T) {
	pemData, _ := testCertificatePEM(t, 3)
	if !certificateFileCandidate("trust.pem", pemData, int64(len(pemData))) {
		t.Fatal("PEM certificate was not a candidate")
	}
	if certificateFileCandidate("testdata/trust.pem", pemData, int64(len(pemData))) {
		t.Fatal("fixture certificate was a candidate")
	}
	if certificateFileCandidate("empty", nil, 0) {
		t.Fatal("empty file was a candidate")
	}

	oversized := repositorySignals(t, "trust.pem", make([]byte, certificateMaxInputBytes+1))
	wanted := Signal{
		Check: checkCertificate,
		Kind:  certificateCoverageKind,
		Name:  "oversized",
		Value: "bytes=8388609; limit=8388608",
		Path:  "trust.pem",
	}
	if !containsExactSignal(oversized, wanted) {
		t.Fatalf("oversized certificate signals missing %#v: %#v", wanted, oversized)
	}
}

func TestRepositoryFileSignalsReportsIncompleteCertificateScan(t *testing.T) {
	malformed := []byte("-----BEGIN CERTIFICATE-----\nbad!\n-----END CERTIFICATE-----\n")
	signals := repositorySignals(t, "bad.pem", malformed)
	coverage := findCertificateSignal(t, signals, certificateCoverageKind, "incomplete")
	if coverage.Value != "malformed_certificate=1" {
		t.Fatalf("certificate coverage = %#v", coverage)
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
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
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

func TestLogDetectsCertificateChangesAcrossHistory(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	first, firstFingerprint := testCertificatePEM(t, 10)
	writeFile(t, repo, "trust.pem", string(first))
	gitRun(t, repo, "add", "trust.pem")
	gitRun(t, repo, "commit", "-m", "Add trust certificate")

	second, secondFingerprint := testCertificatePEM(t, 11)
	writeFile(t, repo, "trust.pem", string(second))
	gitRun(t, repo, "add", "trust.pem")
	gitRun(t, repo, "commit", "-m", "Replace trust certificate")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, expected := range []string{
		"+ Certificate/identity " + firstFingerprint + " at trust.pem",
		"- Certificate/identity " + firstFingerprint + " at trust.pem",
		"+ Certificate/identity " + secondFingerprint + " at trust.pem",
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
		int64(len(data)),
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

func findCertificateSignal(t *testing.T, signals []Signal, kind, name string) Signal {
	t.Helper()
	for _, signal := range signals {
		if signal.Check == checkCertificate && signal.Kind == kind && (name == "" || signal.Name == name) {
			return signal
		}
	}
	t.Fatalf("signal %s/%s %s not found: %#v", checkCertificate, kind, name, signals)
	return Signal{}
}

func testCertificatePEM(t *testing.T, serial int64) ([]byte, string) {
	return testCertificatePEMWithName(t, serial, fmt.Sprintf("Signals Test CA %d", serial))
}

func testCertificatePEMWithName(t *testing.T, serial int64, commonName string) ([]byte, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := pkix.Name{CommonName: commonName}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               name,
		Issuer:                name,
		NotBefore:             time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(fingerprint[:])
}
