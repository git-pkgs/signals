package main

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"

	githistory "github.com/git-pkgs/history"
	pkgmanagers "github.com/git-pkgs/managers"
	"github.com/git-pkgs/managers/definitions"
	"github.com/git-pkgs/manifests"
)

const (
	detectorPackageManagers = "Package-Managers"
	checkPackageManager     = "Package-Manager"
)

type packageManagerDetector struct {
	detector *pkgmanagers.Detector
}

func newPackageManagerDetector() (*packageManagerDetector, error) {
	defs, err := definitions.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("load package manager definitions: %w", err)
	}

	detector := pkgmanagers.NewDetector(pkgmanagers.NewTranslator(), pkgmanagers.NewMockRunner())
	for _, def := range defs {
		detector.Register(def)
	}
	return &packageManagerDetector{detector: detector}, nil
}

func (d *packageManagerDetector) directoriesForChanges(changes []githistory.Change) ([]string, error) {
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		if includePackagePath(change.Path) {
			paths = append(paths, change.Path)
		}
	}
	return d.affectedDirectories(paths)
}

func (d *packageManagerDetector) directoriesForTree(tree fs.FS) ([]string, error) {
	var paths []string
	err := fs.WalkDir(tree, ".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == "." {
			return nil
		}
		if entry.IsDir() {
			if !includePackagePath(filePath) {
				return fs.SkipDir
			}
			return nil
		}
		if includePackagePath(filePath) {
			paths = append(paths, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d.affectedDirectories(paths)
}

func (d *packageManagerDetector) affectedDirectories(paths []string) ([]string, error) {
	directories := make(map[string]bool)
	for _, filePath := range paths {
		matched, err := d.detector.AffectedDirectories(filePath)
		if err != nil {
			return nil, err
		}
		for _, directory := range matched {
			directories[directory] = true
		}
	}

	result := make([]string, 0, len(directories))
	for directory := range directories {
		result = append(result, directory)
	}
	sort.Strings(result)
	return result, nil
}

func (d *packageManagerDetector) signals(tree fs.FS, directories []string) ([]Signal, error) {
	var signals []Signal
	for _, directory := range directories {
		detections, err := d.detector.DetectAllFS(tree, directory, pkgmanagers.FileDetectOptions{
			OnConflict: pkgmanagers.ConflictUseFirst,
		})
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("detect package managers in %s: %w", directory, err)
		}
		for _, detection := range detections {
			signals = append(signals, Signal{
				Check: checkPackageManager,
				Kind:  detection.Ecosystem,
				Name:  detection.Manager,
				Path:  directory,
			})
			signals = appendUnknownPackageFile(signals, directory, "manifest", detection.Ecosystem, detection.Manifest)
			signals = appendUnknownPackageFile(signals, directory, "lockfile", detection.Ecosystem, detection.Lockfile)
		}
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func appendUnknownPackageFile(
	signals []Signal,
	directory, kind, ecosystem, name string,
) []Signal {
	if name == "" {
		return signals
	}
	filePath := path.Join(directory, name)
	if len(manifests.IdentifyAll(filePath)) > 0 {
		return signals
	}
	return append(signals, Signal{
		Check: checkPackageFile,
		Kind:  kind,
		Name:  ecosystem,
		Path:  filePath,
	})
}

func (d *packageManagerDetector) removeSignals(
	signals map[string]Signal,
	directories []string,
	full bool,
) error {
	directorySet := make(map[string]bool, len(directories))
	for _, directory := range directories {
		directorySet[directory] = true
	}

	var remove []string
	for key, signal := range signals {
		switch {
		case signal.Check == checkPackageManager:
			if full || directorySet[signal.Path] {
				remove = append(remove, key)
			}
		case signal.Check == checkPackageFile && len(manifests.IdentifyAll(signal.Path)) == 0:
			if full {
				remove = append(remove, key)
				continue
			}
			affected, err := d.detector.AffectedDirectories(signal.Path)
			if err != nil {
				return err
			}
			for _, directory := range affected {
				if directorySet[directory] {
					remove = append(remove, key)
					break
				}
			}
		}
	}
	for _, key := range remove {
		delete(signals, key)
	}
	return nil
}
