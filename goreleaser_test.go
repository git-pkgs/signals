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
	testGoReleaserChangeAdded   = "added"
	testGoReleaserChangeRemoved = "removed"
	testGoReleaserLogCommand    = "log"
)

func TestGoReleaserSignals(t *testing.T) {
	data := []byte(`version: 2
signs:
  - artifacts: checksum
  - cmd: ignored
    artifacts: none
docker_signs:
  - {}
  - cmd: notation
    artifacts: manifests
binary_signs:
  - {}
sboms:
  - {}
  - cmd: cyclonedx
    artifacts: binary
  - disable: true
    cmd: disabled
  - artifacts: none
    cmd: disabled-by-artifact
`)
	signals := repositorySignals(t, testGoReleaserPath, data)
	for _, wanted := range []Signal{
		{Check: checkArtifactSigning, Kind: goreleaserKindSign, Name: goreleaserGPGCommand, Value: "checksum", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindDockerSign, Name: "cosign", Value: "docker-v2", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindDockerSign, Name: "notation", Value: "manifests", Path: testGoReleaserPath},
		{Check: checkArtifactSigning, Kind: goreleaserKindBinarySign, Name: goreleaserGPGCommand, Value: "binary", Path: testGoReleaserPath},
		{Check: checkSBOMGeneration, Kind: goreleaserKindSBOM, Name: "syft", Value: "archive", Path: testGoReleaserPath},
		{Check: checkSBOMGeneration, Kind: goreleaserKindSBOM, Name: "cyclonedx", Value: "binary", Path: testGoReleaserPath},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	if len(signals) != 6 {
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

	writeFile(t, repo, testGoReleaserPath, "version: 2\nsigns:\n  - artifacts: checksum\nsboms:\n  - {}\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add release evidence")

	if err := os.Remove(filepath.Join(repo, testGoReleaserPath)); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-u")
	gitRun(t, repo, "commit", "-m", "Remove release evidence")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testGoReleaserLogCommand, testJSONLFlag, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
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
	removed := findJSONLRecord(t, records, "Remove release evidence")
	for _, expected := range []jsonlChange{
		{Change: testGoReleaserChangeAdded, Check: checkArtifactSigning, Kind: goreleaserKindSign, Name: goreleaserGPGCommand, Value: "checksum", Path: testGoReleaserPath},
		{Change: testGoReleaserChangeAdded, Check: checkSBOMGeneration, Kind: goreleaserKindSBOM, Name: "syft", Value: "archive", Path: testGoReleaserPath},
	} {
		if !containsExactJSONLChange(added.Changes, expected) {
			t.Errorf("added record missing %#v:\n%s", expected, stdout.String())
		}
		expected.Change = testGoReleaserChangeRemoved
		if !containsExactJSONLChange(removed.Changes, expected) {
			t.Errorf("removed record missing %#v:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}
