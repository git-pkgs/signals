package main

import (
	"strings"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

func TestPackageManagerSignalsAddManagerAndUnknownPackageFile(t *testing.T) {
	const projectDir = "apps/tool"

	detector, err := newPackageManagerDetector()
	if err != nil {
		t.Fatal(err)
	}
	tree := fstest.MapFS{
		"apps/tool/example.nimble": {Data: []byte("version = \"0.1.0\"\n")},
		"apps/tool/nimble.lock":    {Data: []byte("{}\n")},
	}

	signals, err := detector.signals(tree, []string{projectDir})
	if err != nil {
		t.Fatalf("package manager signals: %v", err)
	}

	manager := findPackageSignal(t, signals, checkPackageManager, "nimble", "nimble")
	if manager.Path != projectDir {
		t.Errorf("manager path = %q, want apps/tool", manager.Path)
	}
	lockfile := findPackageSignal(t, signals, checkPackageFile, "lockfile", "nimble")
	if lockfile.Path != "apps/tool/nimble.lock" {
		t.Errorf("lockfile path = %q, want apps/tool/nimble.lock", lockfile.Path)
	}
}

func TestPackageManagerDirectoriesForChanges(t *testing.T) {
	detector, err := newPackageManagerDetector()
	if err != nil {
		t.Fatal(err)
	}

	directories, err := detector.directoriesForChanges([]githistory.Change{
		{Path: "README.md"},
		{Path: "services/api/nimble.lock"},
		{Path: "vendor/example/nimble.lock"},
	})
	if err != nil {
		t.Fatalf("package manager directories: %v", err)
	}
	if len(directories) != 1 || directories[0] != "services/api" {
		t.Fatalf("directories = %#v, want [services/api]", directories)
	}
}

func TestPackageManagerDirectoriesForTreeSkipExcludedPaths(t *testing.T) {
	detector, err := newPackageManagerDetector()
	if err != nil {
		t.Fatal(err)
	}
	tree := fstest.MapFS{
		"apps/tool/example.nimble":      {Data: []byte("version = \"0.1.0\"\n")},
		"vendor/example/example.nimble": {Data: []byte("version = \"0.1.0\"\n")},
	}

	directories, err := detector.directoriesForTree(tree)
	if err != nil {
		t.Fatalf("package manager directories: %v", err)
	}
	if len(directories) != 1 || directories[0] != "apps/tool" {
		t.Fatalf("directories = %#v, want [apps/tool]", directories)
	}
}

func TestPackageManagerRemovalOnlyAffectsChangedDirectory(t *testing.T) {
	detector, err := newPackageManagerDetector()
	if err != nil {
		t.Fatal(err)
	}
	tree := fstest.MapFS{
		"example.nimble":              {Data: []byte("version = \"0.1.0\"\n")},
		"nimble.lock":                 {Data: []byte("{}\n")},
		"services/api/example.nimble": {Data: []byte("version = \"0.1.0\"\n")},
		"services/api/nimble.lock":    {Data: []byte("{}\n")},
	}
	signals, err := detector.signals(tree, []string{".", "services/api"})
	if err != nil {
		t.Fatalf("package manager signals: %v", err)
	}
	state := make(map[string]Signal)
	addSignals(state, signals)

	if err := detector.removeSignals(state, []string{"."}, false); err != nil {
		t.Fatalf("remove package manager signals: %v", err)
	}
	for _, signal := range state {
		if signal.Path == "." || !strings.HasPrefix(signal.Path, "services/api") {
			t.Fatalf("unexpected remaining signal: %#v", signal)
		}
	}
}
