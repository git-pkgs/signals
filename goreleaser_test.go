package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testGoReleaserPath          = ".goreleaser.yaml"
	testGoReleaserChangeRemoved = "removed"
)

func TestGoReleaserSignals(t *testing.T) {
	data := []byte(`version: 2
signs:
  - artifacts: checksum
    ids: [ignored-for-checksum]
  - cmd: ignored
    artifacts: none
docker_signs:
  - ids: [container]
  - cmd: notation
    artifacts: manifests
binary_signs:
  - ids: [rust, go]
sboms:
  - ids: [rust]
  - cmd: cyclonedx
    artifacts: binary
    ids: [python]
  - disable: true
    cmd: disabled
  - artifacts: none
    cmd: disabled-by-artifact
nfpms:
  - id: packages
    ids: [rust, go]
    formats: [rpm, deb, apk, msix, archlinux]
    rpm:
      signature:
        key_file: rpm.asc
    deb:
      signature:
        key_file: deb.asc
    apk:
      signature:
        key_file: apk.pem
    msix:
      signature:
        pfx_file: windows.pfx
  - formats: [termux.deb]
    builds: [android]
    overrides:
      termux.deb:
        deb:
          signature:
            key_file: termux.asc
srpm:
  enabled: true
  signature:
    key_file: source-rpm.asc
`)
	signals := repositorySignals(t, testGoReleaserPath, data)
	for _, wanted := range []Signal{
		{Check: checkArtifactSigning, Kind: goreleaserKindSign, Name: goreleaserGPGCommand, Value: "checksum", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindDockerSign, Name: "cosign", Value: "docker-v2; ids=container", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindDockerSign, Name: "notation", Value: "manifests", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindBinarySign, Name: goreleaserGPGCommand, Value: "binary; ids=go,rust", Path: testGoReleaserPath},
		{Check: checkSBOMGeneration, Kind: goreleaserKindSBOM, Name: "syft", Value: "archive; ids=rust", Path: testGoReleaserPath},
		{Check: checkSBOMGeneration, Kind: goreleaserKindSBOM, Name: "cyclonedx", Value: "binary; ids=python", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "rpm; id=packages; ids=go,rust", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "deb; id=packages; ids=go,rust", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "apk; id=packages; ids=go,rust", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "msix; id=packages; ids=go,rust", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "termux.deb; id=default; ids=android", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "srpm", Path: testGoReleaserPath},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	if len(signals) != 12 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestGoReleaserSignalsIgnoreUnconfiguredAndBundledFiles(t *testing.T) {
	for _, test := range []struct {
		path string
		data string
	}{
		{path: testGoReleaserPath, data: "version: 2\n"},
		{path: testGoReleaserPath, data: "signs:\n  - {}\n"},
		{path: testGoReleaserPath, data: "nfpms:\n  - formats: [rpm]\n    deb:\n      signature:\n        key_file: signing.asc\n"},
		{path: testGoReleaserPath, data: "nfpms:\n  - rpm:\n      signature:\n        key_file: signing.asc\n"},
		{path: testGoReleaserPath, data: "srpm:\n  signature:\n    key_file: signing.asc\n"},
		{path: testGoReleaserPath, data: "not: [valid\n"},
		{path: "vendor/example/.goreleaser.yaml", data: "sboms:\n  - {}\n"},
	} {
		if signals := repositorySignals(t, test.path, []byte(test.data)); len(signals) != 0 {
			t.Errorf("%s signals = %#v", test.path, signals)
		}
	}
}

func TestLogTracksGoReleaserSupplyChainConfiguration(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, testGoReleaserPath, goreleaserHistoryConfig("go"))
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add release evidence")

	writeFile(t, repo, testGoReleaserPath, goreleaserHistoryConfig("rust"))
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Change selected release build")

	if err := os.Remove(filepath.Join(repo, testGoReleaserPath)); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-u")
	gitRun(t, repo, "commit", "-m", "Remove release evidence")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testJSONLFlag, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
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
	added := findJSONLRecord(t, records, "Add release evidence")
	changed := findJSONLRecord(t, records, "Change selected release build")
	removed := findJSONLRecord(t, records, "Remove release evidence")
	for _, expected := range []jsonlChange{
		{Change: testChangeAdded, Check: checkArtifactSigning, Kind: goreleaserKindSign, Name: goreleaserGPGCommand, Value: "archive; ids=go", Path: testGoReleaserPath},
		{Change: testChangeAdded, Check: checkSBOMGeneration, Kind: goreleaserKindSBOM, Name: "syft", Value: "archive; ids=go", Path: testGoReleaserPath},
		{Change: testChangeAdded, Check: checkArtifactSigning, Kind: goreleaserKindPackageSign, Name: goreleaserNFPMCommand, Value: "deb; id=packages; ids=go", Path: testGoReleaserPath},
	} {
		if !containsExactJSONLChange(added.Changes, expected) {
			t.Errorf("added record missing %#v:\n%s", expected, stdout.String())
		}
		old := expected
		old.Change = testGoReleaserChangeRemoved
		if !containsExactJSONLChange(changed.Changes, old) {
			t.Errorf("changed record missing %#v:\n%s", old, stdout.String())
		}
		current := expected
		current.Value = strings.Replace(current.Value, "ids=go", "ids=rust", 1)
		if !containsExactJSONLChange(changed.Changes, current) {
			t.Errorf("changed record missing %#v:\n%s", current, stdout.String())
		}
		current.Change = testGoReleaserChangeRemoved
		if !containsExactJSONLChange(removed.Changes, current) {
			t.Errorf("removed record missing %#v:\n%s", current, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func goreleaserHistoryConfig(id string) string {
	return `version: 2
signs:
  - artifacts: archive
    ids: [` + id + `]
sboms:
  - ids: [` + id + `]
nfpms:
  - id: packages
    ids: [` + id + `]
    formats: [deb]
    deb:
      signature:
        key_file: signing.asc
`
}
