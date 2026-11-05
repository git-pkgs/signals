package main

import (
	"strings"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

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
	summary := findPackageSignal(t, signals, checkDependencyPinning, "npm", "")
	if summary.Value != "exact=1; ranged=1; unparsed=0" {
		t.Errorf("pinning summary = %q", summary.Value)
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
	if !strings.Contains(integrity.Value, "verified=1") {
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
