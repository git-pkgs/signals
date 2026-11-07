package main

import (
	"strings"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

const exactAndRangedSummary = "exact=1; ranged=1; unparsed=0"

func TestPackageFileSignalsFindsExactManifestPins(t *testing.T) {
	signals := packageFileSignals(packageJSONPath, []byte(`{
      "name": "example",
      "dependencies": {
        "exact": "1.2.3",
        "ranged": "^2.0.0"
      }
    }`))

	file := findPackageSignal(t, signals, checkPackageFile, "manifest", "npm")
	if file.Path != packageJSONPath {
		t.Errorf("package file path = %q", file.Path)
	}
	pin := findPackageSignal(t, signals, checkDependencyPin, "npm", "pkg:npm/exact")
	if pin.Value != "1.2.3" {
		t.Errorf("exact pin = %q, want 1.2.3", pin.Value)
	}
	constraint := findPackageSignal(t, signals, checkDependencyConstraint, "npm", "pkg:npm/ranged")
	if constraint.Value != "^2.0.0" {
		t.Errorf("ranged constraint = %q, want ^2.0.0", constraint.Value)
	}
	summary := findPackageSignal(t, signals, checkDependencyPinning, "npm", "")
	if summary.Value != exactAndRangedSummary {
		t.Errorf("pinning summary = %q", summary.Value)
	}
}

func TestPackageFileSignalsFindsManifestLicenses(t *testing.T) {
	signals := packageFileSignals("Cargo.toml", []byte(`[package]
name = "example"
version = "1.0.0"
license = "MIT OR Apache-2.0"
license-file = "COPYING"
`))

	findPackageSignal(t, signals, checkLicense, signalKindDeclaration, "MIT OR Apache-2.0")
	reference := findPackageSignal(t, signals, checkLicense, signalKindFileReference, "")
	if reference.Value != "COPYING" {
		t.Errorf("license file reference = %q, want COPYING", reference.Value)
	}
}

func TestPackageFileSignalsFindsPublicationProvenance(t *testing.T) {
	tests := []struct {
		name    string
		content string
		value   string
		found   bool
	}{
		{name: packageProvenanceEnabled, content: `{"name":"example","publishConfig":{"provenance":true}}`, value: packageProvenanceEnabled, found: true},
		{name: packageProvenanceDisabled, content: `{"name":"example","publishConfig":{"provenance":false}}`, value: packageProvenanceDisabled, found: true},
		{name: "absent", content: `{"name":"example"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signals := packageFileSignals(packageJSONPath, []byte(test.content))
			for _, signal := range signals {
				if signal.Check != checkPackageProvenance {
					continue
				}
				if !test.found {
					t.Fatalf("unexpected provenance signal: %#v", signal)
				}
				if signal.Kind != packagingNameNPM || signal.Name != testPackageName || signal.Value != test.value {
					t.Fatalf("provenance signal = %#v", signal)
				}
				return
			}
			if test.found {
				t.Fatalf("provenance signal missing: %#v", signals)
			}
		})
	}
}

func TestPackageFileSignalsFindsNPMRCProvenance(t *testing.T) {
	signals := packageFileSignals(".npmrc", []byte("provenance=true\n"))
	signal := findPackageSignal(t, signals, checkPackageProvenance, packagingNameNPM, "")
	if signal.Value != packageProvenanceEnabled {
		t.Fatalf("provenance signal = %#v", signal)
	}
	findPackageSignal(t, signals, checkPackageFile, "supplement", packagingNameNPM)
}

func TestRemovePackageSignalsKeepsWorkflowProvenance(t *testing.T) {
	manifest := Signal{
		Check: checkPackageProvenance,
		Kind:  packagingNameNPM,
		Name:  testPackageName,
		Path:  packageJSONPath,
	}
	workflow := Signal{
		Check: checkPackageProvenance,
		Kind:  "npm-flag",
		Name:  "publish",
		Path:  ".github/workflows/release.yml",
	}
	signals := map[string]Signal{
		signalKey(manifest): manifest,
		signalKey(workflow): workflow,
	}

	removePackageSignals(signals, nil)

	if hasSignal(signals, manifest) {
		t.Fatalf("manifest provenance remains: %#v", signals)
	}
	if !hasSignal(signals, workflow) {
		t.Fatalf("workflow provenance was removed: %#v", signals)
	}
}

func TestPackageAndRepositoryLicenseSignalsHaveSeparateOwnership(t *testing.T) {
	signals := map[string]Signal{}
	for _, signal := range []Signal{
		{Check: checkLicense, Kind: signalKindDeclaration, Name: testMITLicenseID, Path: packageJSONPath},
		{Check: checkLicense, Kind: signalKindLicense, Name: testMITLicenseID, Path: testLicensePath},
		{Check: checkLicense, Kind: signalKindNotice, Path: "NOTICE"},
	} {
		signals[signalKey(signal)] = signal
	}

	removePackageSignals(signals, nil)
	if len(signals) != 2 {
		t.Fatalf("after package removal = %#v", signals)
	}
	removeRepositoryLicenseSignals(signals, nil)
	if len(signals) != 0 {
		t.Fatalf("after repository removal = %#v", signals)
	}
}

func TestPackageFileSignalsClassifiesGitHubActionPins(t *testing.T) {
	const pinned = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	signals := packageFileSignals(".github/workflows/ci.yml", []byte(`jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@`+pinned+`
      - uses: actions/setup-go@v6
`))

	pin := findPackageSignal(t, signals, checkDependencyPin, "github-actions", "pkg:githubactions/actions/checkout")
	if pin.Value != pinned {
		t.Errorf("action pin = %q, want %s", pin.Value, pinned)
	}
	legacy := findPackageSignal(t, signals, checkPinnedDependencies, "GitHubAction", "actions/checkout")
	if legacy.Value != "pinned@"+pinned {
		t.Errorf("pinned action value = %q", legacy.Value)
	}
	unpinned := findPackageSignal(t, signals, checkPinnedDependencies, "GitHubAction", "actions/setup-go")
	if unpinned.Value != "unpinned" {
		t.Errorf("unpinned action value = %q", unpinned.Value)
	}
	constraint := findPackageSignal(t, signals, checkDependencyConstraint, "github-actions", "pkg:githubactions/actions/setup-go")
	if constraint.Value != "v6" {
		t.Errorf("action constraint = %q, want v6", constraint.Value)
	}
	summary := findPackageSignal(t, signals, checkDependencyPinning, "github-actions", "")
	if summary.Value != exactAndRangedSummary {
		t.Errorf("action pinning summary = %q", summary.Value)
	}
}

func TestClassifyDependencyPinRequiresFullGitHubCommitSHA(t *testing.T) {
	tests := []struct {
		name    string
		version string
		pinned  bool
	}{
		{name: "short SHA", version: strings.Repeat("a", 39)},
		{name: "full SHA", version: strings.Repeat("a", 40), pinned: true},
		{name: "long hexadecimal ref", version: strings.Repeat("a", 41)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, pinned, classified := classifyDependencyPin(tt.version, "github-actions")
			if version != tt.version || pinned != tt.pinned || !classified {
				t.Fatalf("classifyDependencyPin() = %q, %t, %t", version, pinned, classified)
			}
		})
	}
}

func TestPackageFileSignalsClassifiesContainerDigests(t *testing.T) {
	const digest = "sha256:9cb31e2e37ea84c54fd72af82d7d454d24f714bd7ee2b7eb350f3231b3e1f5a0"
	signals := packageFileSignals("Dockerfile", []byte("FROM ruby:3.4\nFROM alpine@"+digest+"\n"))

	pin := findPackageSignal(t, signals, checkDependencyPin, dockerName, "pkg:docker/alpine")
	if pin.Value != digest {
		t.Errorf("container pin = %q, want %s", pin.Value, digest)
	}
	pinned := findPackageSignal(t, signals, checkPinnedDependencies, "containerImage", "alpine")
	if pinned.Value != "pinned@"+digest {
		t.Errorf("pinned container value = %q", pinned.Value)
	}
	unpinned := findPackageSignal(t, signals, checkPinnedDependencies, "containerImage", "ruby")
	if unpinned.Value != "unpinned" {
		t.Errorf("unpinned container value = %q", unpinned.Value)
	}
	constraint := findPackageSignal(t, signals, checkDependencyConstraint, dockerName, "pkg:docker/ruby")
	if constraint.Value != "3.4" {
		t.Errorf("container constraint = %q, want 3.4", constraint.Value)
	}
	summary := findPackageSignal(t, signals, checkDependencyPinning, dockerName, "")
	if summary.Value != exactAndRangedSummary {
		t.Errorf("container pinning summary = %q", summary.Value)
	}
}

func TestPackageFileSignalsSummarizesLockfileIntegrity(t *testing.T) {
	signals := packageFileSignals("package-lock.json", []byte(`{
      "name": "example",
      "lockfileVersion": 3,
      "packages": {
        "": {"dependencies": {"exact": "1.2.3"}},
        "node_modules/exact": {
          "version": "1.2.3",
          "integrity": "sha512-example"
        }
      }
    }`))

	findPackageSignal(t, signals, checkPackageFile, "lockfile", "npm")
	pinning := findPackageSignal(t, signals, checkDependencyPinning, "npm", "")
	if !strings.Contains(pinning.Value, "resolved=1") {
		t.Errorf("lockfile pinning = %q", pinning.Value)
	}
	integrity := findPackageSignal(t, signals, checkLockfileIntegrity, "npm", "")
	if integrity.Value != "declared=1; total=1" {
		t.Errorf("lockfile integrity = %q", integrity.Value)
	}
}

func TestAllPackageSignalsSkipsFixturePackages(t *testing.T) {
	signals, err := allPackageSignals(fstest.MapFS{
		"apps/web/package.json":       {Data: []byte(`{"name":"web"}`)},
		"testdata/package.json":       {Data: []byte(`{"name":"fixture"}`)},
		"vendor/example/package.json": {Data: []byte(`{"name":"vendored"}`)},
	})
	if err != nil {
		t.Fatalf("allPackageSignals: %v", err)
	}

	if len(signals) != 1 || signals[0].Path != "apps/web/package.json" {
		t.Fatalf("package signals = %#v", signals)
	}
}

func TestPackageSignalsForChangesUsesBlobCache(t *testing.T) {
	cache := make(map[packageCacheKey][]Signal)
	changes := []githistory.Change{{Path: "go.mod", NewOID: strings.Repeat("a", 40)}}
	tree := fstest.MapFS{"go.mod": {Data: []byte("module example.com/project\n")}}

	first, paths, err := packageSignalsForChanges(tree, changes, cache)
	if err != nil {
		t.Fatalf("packageSignalsForChanges: %v", err)
	}
	if len(first) == 0 || len(paths) != 1 {
		t.Fatalf("signals = %#v, paths = %#v", first, paths)
	}

	second, _, err := packageSignalsForChanges(fstest.MapFS{}, changes, cache)
	if err != nil {
		t.Fatalf("cached packageSignalsForChanges: %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("cached signals = %#v, want %#v", second, first)
	}
}

func findPackageSignal(t *testing.T, signals []Signal, check, kind, name string) Signal {
	t.Helper()
	for _, signal := range signals {
		if signal.Check == check && signal.Kind == kind && signal.Name == name {
			return signal
		}
	}
	t.Fatalf("signal %s/%s %s not found: %#v", check, kind, name, signals)
	return Signal{}
}
