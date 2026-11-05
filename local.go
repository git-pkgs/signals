package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	gitbrief "github.com/git-pkgs/brief"
	briefdetect "github.com/git-pkgs/brief/detect"
	"github.com/git-pkgs/brief/kb"
	githistory "github.com/git-pkgs/history"
	"github.com/git-pkgs/reuse"
	"github.com/git-pkgs/roles"
	"github.com/git-pkgs/secrets/scanner"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
)

const (
	checkBuild             = "Build"
	checkCI                = "CI"
	checkPreCommit         = "Pre-Commit"
	checkREUSE             = "REUSE"
	checkSecret            = "Secret"
	checkSecretsManagement = "Secrets-Management"
	checkSecurityTool      = "Security-Tool"

	detectorBrief = "Brief"
)

var localDetectorNames = []string{detectorBrief, checkSecret, checkREUSE}

var reuseMetadataMarkers = [...][]byte{
	[]byte("SPDX-License-Identifier:"),
	[]byte("SPDX-FileCopyrightText:"),
	[]byte("SPDX-FileContributor:"),
}

type localDetectors struct {
	repo          *githistory.Repo
	knowledge     *kb.KnowledgeBase
	briefImpact   *gitbrief.Report
	secretScanner *scanner.Scanner
	secretCache   map[secretCacheKey][]Signal
}

type secretCacheKey struct {
	oid  string
	path string
}

type reuseFile struct {
	licenseExpressions []string
	covered            bool
	hasMetadata        bool
}

func newLocalDetectors(ctx context.Context, repo *githistory.Repo) (*localDetectors, error) {
	knowledge, err := kb.Load(gitbrief.KnowledgeFS)
	if err != nil {
		return nil, fmt.Errorf("load Brief knowledge base: %w", err)
	}
	secretScanner, err := scanner.New(ctx, scanner.Options{})
	if err != nil {
		return nil, fmt.Errorf("create secret scanner: %w", err)
	}
	knowledge = signalKnowledgeBase(knowledge)
	detectors := &localDetectors{
		repo:          repo,
		knowledge:     knowledge,
		secretScanner: secretScanner,
		secretCache:   make(map[secretCacheKey][]Signal),
	}
	detectors.briefImpact = newBriefImpactReport(knowledge)
	return detectors, nil
}

func signalKnowledgeBase(source *kb.KnowledgeBase) *kb.KnowledgeBase {
	filtered := &kb.KnowledgeBase{
		ByName:        make(map[string]*kb.ToolDef),
		ByCategory:    make(map[string][]*kb.ToolDef),
		Ecosystems:    make(map[string][]*kb.ToolDef),
		ManifestFiles: append([]string(nil), source.ManifestFiles...),
	}
	for _, tool := range source.Tools {
		_, _, _, selected := briefSignalType(tool.Tool.Name, tool.Tool.Category, taxonomyFromTool(tool))
		if tool.Tool.Category != "language" && !selected {
			continue
		}
		filtered.Tools = append(filtered.Tools, tool)
		filtered.ByName[tool.Tool.Name] = tool
		filtered.ByCategory[tool.Tool.Category] = append(filtered.ByCategory[tool.Tool.Category], tool)
		for _, ecosystem := range tool.Detect.Ecosystems {
			filtered.Ecosystems[ecosystem] = append(filtered.Ecosystems[ecosystem], tool)
		}
	}
	return filtered
}

func (d *localDetectors) Close() error {
	return d.secretScanner.Close()
}

func (d *localDetectors) detect(
	ctx context.Context,
	commit *object.Commit,
	parent commitState,
	changes []githistory.Change,
	forceFull bool,
	languagesChanged bool,
	cache *blobCache,
	stats *scanStats,
) (commitState, error) {
	current := cloneCommitState(parent)
	briefFull := forceFull || parent.errors[detectorBrief] != ""
	briefRun := briefFull || d.briefAffected(changes, languagesChanged)
	secretFull := forceFull || parent.errors[checkSecret] != ""
	reuseFull := forceFull || parent.errors[checkREUSE] != "" || reuseMetadataChanged(changes)
	if !reuseFull && !parent.reuseActive {
		var err error
		reuseFull, err = reuseChangeMayActivate(changes, cache)
		if err != nil {
			return commitState{}, err
		}
	}
	reuseRun := reuseFull || parent.reuseActive && len(changes) > 0

	var tree fs.FS
	if briefRun || reuseRun {
		var err error
		tree, err = d.repo.TreeFS(commit.Hash)
		if err != nil {
			return commitState{}, err
		}
	}

	d.runBrief(tree, briefRun, briefFull, &current, stats)
	d.runSecrets(ctx, commit, changes, secretFull, cache, &current, stats)
	d.runREUSE(tree, changes, reuseRun, reuseFull, &current, stats)
	return current, nil
}

func (d *localDetectors) runBrief(
	tree fs.FS,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorBrief]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()
	signals, err := d.briefSignals(tree)
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorBrief] = err.Error()
		return
	}
	delete(current.errors, detectorBrief)
	removeBriefSignals(current.signals)
	addSignals(current.signals, signals)
}

func (d *localDetectors) briefSignals(tree fs.FS) ([]Signal, error) {
	report, err := briefdetect.NewFS(d.knowledge, tree).Run()
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, detections := range report.Tools {
		for _, detection := range detections {
			check, kind, name, ok := briefSignalType(detection.Name, detection.Category, detection.Taxonomy)
			if !ok {
				continue
			}
			paths := append([]string(nil), detection.ConfigFiles...)
			if detection.Lockfile != "" {
				paths = append(paths, detection.Lockfile)
			}
			if len(paths) == 0 {
				signals = append(signals, Signal{Check: check, Kind: kind, Name: name})
				continue
			}
			for _, configPath := range paths {
				signals = append(signals, Signal{Check: check, Kind: kind, Name: name, Path: configPath})
			}
		}
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func (d *localDetectors) briefAffected(changes []githistory.Change, languagesChanged bool) bool {
	if len(changes) == 0 {
		return false
	}
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		labels, err := roles.Match(change.Path)
		if err == nil && (labels.Has(roles.Vendor) || labels.Has(roles.Fixture) ||
			labels.Has(roles.Cache) || labels.Has(roles.BuildOutput)) {
			continue
		}
		paths = append(paths, change.Path)
	}
	if len(paths) == 0 {
		return false
	}
	filtered := briefdetect.FilterByChangedFiles(d.briefImpact, d.knowledge, paths)
	for _, detections := range filtered.Tools {
		if len(detections) > 0 {
			return true
		}
	}
	return languagesChanged && len(filtered.Languages) > 0
}

func newBriefImpactReport(knowledge *kb.KnowledgeBase) *gitbrief.Report {
	report := &gitbrief.Report{Tools: make(map[string][]gitbrief.Detection)}
	for _, tool := range knowledge.Tools {
		detection := gitbrief.Detection{Name: tool.Tool.Name, Category: tool.Tool.Category}
		if tool.Tool.Category == "language" {
			report.Languages = append(report.Languages, detection)
			continue
		}
		if _, _, _, ok := briefSignalType(tool.Tool.Name, tool.Tool.Category, taxonomyFromTool(tool)); ok {
			report.Tools[tool.Tool.Category] = append(report.Tools[tool.Tool.Category], detection)
		}
	}
	return report
}

func taxonomyFromTool(tool *kb.ToolDef) *gitbrief.Taxonomy {
	if tool.Taxonomy.Empty() {
		return nil
	}
	return &gitbrief.Taxonomy{
		Role:       tool.Taxonomy.Role,
		Function:   tool.Taxonomy.Function,
		Layer:      tool.Taxonomy.Layer,
		Domain:     tool.Taxonomy.Domain,
		Audience:   tool.Taxonomy.Audience,
		Technology: tool.Taxonomy.Technology,
	}
}

func briefSignalType(
	name, category string,
	taxonomy *gitbrief.Taxonomy,
) (check, kind, signalName string, ok bool) {
	switch {
	case category == "ci":
		return checkCI, name, "", true
	case name == "SOPS":
		return checkSecretsManagement, name, "", true
	case category == "security":
		kind = "tool"
		if taxonomy != nil && len(taxonomy.Function) > 0 {
			kind = taxonomy.Function[0]
		}
		return checkSecurityTool, kind, name, true
	case taxonomy != nil && containsString(taxonomy.Role, "build-tool"):
		return checkBuild, name, "", true
	case isPreCommitTool(name):
		return checkPreCommit, name, "", true
	default:
		return "", "", "", false
	}
}

func isPreCommitTool(name string) bool {
	switch name {
	case "pre-commit", "Lefthook", "Husky", "Overcommit":
		return true
	default:
		return false
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func removeBriefSignals(signals map[string]Signal) {
	for key, signal := range signals {
		switch signal.Check {
		case checkBuild, checkCI, checkPreCommit, checkSecretsManagement, checkSecurityTool:
			delete(signals, key)
		}
	}
}

func (d *localDetectors) runSecrets(
	ctx context.Context,
	commit *object.Commit,
	changes []githistory.Change,
	forceFull bool,
	cache *blobCache,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[checkSecret]
	if !forceFull && len(changes) == 0 {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()
	signals, paths, err := d.secretSignals(ctx, commit, changes, forceFull, cache)
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[checkSecret] = err.Error()
		return
	}
	delete(current.errors, checkSecret)
	if forceFull {
		removeCheckSignals(current.signals, checkSecret)
	} else {
		removePathSignals(current.signals, checkSecret, paths)
	}
	addSignals(current.signals, signals)
}

func (d *localDetectors) secretSignals(
	ctx context.Context,
	commit *object.Commit,
	changes []githistory.Change,
	forceFull bool,
	cache *blobCache,
) ([]Signal, map[string]bool, error) {
	paths := make(map[string]bool)
	var signals []Signal
	if forceFull {
		tree, err := commit.Tree()
		if err != nil {
			return nil, nil, err
		}
		iter := tree.Files()
		defer iter.Close()
		err = iter.ForEach(func(file *object.File) error {
			if !secretFileMode(file.Mode) {
				return nil
			}
			found, err := d.scanSecretFile(ctx, file, cache)
			if err != nil {
				return fmt.Errorf("scan %s for secrets: %w", file.Name, err)
			}
			signals = append(signals, found...)
			return nil
		})
		return signals, paths, err
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, nil, err
	}
	for _, change := range changes {
		if paths[change.Path] {
			continue
		}
		paths[change.Path] = true
		mode, err := filemode.New(change.NewMode)
		if err != nil {
			return nil, nil, fmt.Errorf("parse mode for %s: %w", change.Path, err)
		}
		if !secretFileMode(mode) {
			continue
		}
		file, err := tree.File(change.Path)
		if errors.Is(err, object.ErrFileNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		found, err := d.scanSecretFile(ctx, file, cache)
		if err != nil {
			return nil, nil, fmt.Errorf("scan %s for secrets: %w", change.Path, err)
		}
		signals = append(signals, found...)
	}
	return signals, paths, nil
}

func secretFileMode(mode filemode.FileMode) bool {
	return mode == filemode.Regular || mode == filemode.Deprecated || mode == filemode.Executable
}

func (d *localDetectors) scanSecretFile(
	ctx context.Context,
	file *object.File,
	cache *blobCache,
) ([]Signal, error) {
	key := secretCacheKey{oid: file.Hash.String(), path: file.Name}
	if signals, ok := d.secretCache[key]; ok {
		return signals, nil
	}
	data, err := cache.dataFor(file)
	if err != nil {
		return nil, err
	}
	result, err := d.secretScanner.Scan(ctx, data, file.Name)
	if err != nil {
		return nil, err
	}
	signals := make([]Signal, 0, len(result.Findings))
	for _, finding := range result.Findings {
		line := uint(0)
		if finding.StartLine > 0 {
			line = uint(finding.StartLine)
		}
		signals = append(signals, Signal{
			Check: checkSecret,
			Kind:  finding.RuleID,
			Value: "[redacted]",
			Path:  file.Name,
			Line:  line,
		})
	}
	sortSignals(signals)
	signals = deduplicateSignals(signals)
	d.secretCache[key] = signals
	return signals, nil
}

func (d *localDetectors) runREUSE(
	tree fs.FS,
	changes []githistory.Change,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[checkREUSE]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()
	files, signals, err := reuseSignals(tree, current.reuseFiles, changes, forceFull)
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[checkREUSE] = err.Error()
		return
	}
	delete(current.errors, checkREUSE)
	removeCheckSignals(current.signals, checkREUSE)
	addSignals(current.signals, signals)
	current.reuseActive = len(signals) > 0
	if current.reuseActive {
		current.reuseFiles = files
	} else {
		current.reuseFiles = make(map[string]reuseFile)
	}
}

func reuseSignals(
	tree fs.FS,
	parent map[string]reuseFile,
	changes []githistory.Change,
	full bool,
) (map[string]reuseFile, []Signal, error) {
	project, err := reuse.OpenProjectFS(tree)
	if err != nil {
		return nil, nil, err
	}
	files := make(map[string]reuseFile)
	if full {
		allInfo, err := project.AllReuseInfo()
		if err != nil {
			return nil, nil, err
		}
		for filePath, info := range allInfo {
			files[filePath] = newReuseFile(info)
		}
	} else {
		files = cloneReuseFiles(parent)
		seen := make(map[string]bool, len(changes))
		for _, change := range changes {
			if seen[change.Path] {
				continue
			}
			seen[change.Path] = true
			delete(files, change.Path)
			info, err := fs.Stat(tree, change.Path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			if !info.Mode().IsRegular() || info.Size() == 0 || !reuse.IsCoveredFile(change.Path) {
				continue
			}
			reuseInfo, err := project.ReuseInfoOf(change.Path)
			if err != nil {
				return nil, nil, err
			}
			files[change.Path] = newReuseFile(reuseInfo)
		}
	}
	return files, reuseStateSignals(files, project), nil
}

func newReuseFile(info reuse.ReuseInfo) reuseFile {
	expressions := append([]string(nil), info.LicenseExpressions...)
	sort.Strings(expressions)
	return reuseFile{
		licenseExpressions: expressions,
		covered:            info.HasLicense() && info.HasCopyright(),
		hasMetadata:        !info.IsEmpty(),
	}
}

func cloneReuseFiles(files map[string]reuseFile) map[string]reuseFile {
	clone := make(map[string]reuseFile, len(files))
	for filePath, info := range files {
		clone[filePath] = info
	}
	return clone
}

func reuseStateSignals(files map[string]reuseFile, project *reuse.Project) []Signal {
	covered := 0
	hasMetadata := len(project.ReuseTOMLs) > 0 || project.Dep5 != nil
	signals := make([]Signal, 0, len(files)+len(project.ReuseTOMLs))
	for filePath, info := range files {
		if info.covered {
			covered++
		}
		hasMetadata = hasMetadata || info.hasMetadata
		if len(info.licenseExpressions) > 0 {
			signals = append(signals, Signal{
				Check: checkREUSE,
				Kind:  "declaration",
				Value: strings.Join(info.licenseExpressions, ", "),
				Path:  filePath,
			})
		}
	}
	if hasMetadata {
		signals = append(signals, Signal{
			Check: checkREUSE,
			Kind:  "coverage",
			Value: fmt.Sprintf("%d/%d", covered, len(files)),
		})
	}
	for directory := range project.ReuseTOMLs {
		configPath := "REUSE.toml"
		if directory != "." {
			configPath = path.Join(directory, configPath)
		}
		signals = append(signals, Signal{Check: checkREUSE, Kind: "toml", Path: configPath})
	}
	if project.Dep5 != nil {
		signals = append(signals, Signal{Check: checkREUSE, Kind: "dep5", Path: ".reuse/dep5"})
	}
	sortSignals(signals)
	return signals
}

func reuseMetadataChanged(changes []githistory.Change) bool {
	for _, change := range changes {
		if path.Base(change.Path) == "REUSE.toml" ||
			change.Path == ".reuse/dep5" ||
			strings.HasSuffix(change.Path, ".license") {
			return true
		}
	}
	return false
}

func reuseChangeMayActivate(changes []githistory.Change, cache *blobCache) (bool, error) {
	for _, change := range changes {
		mode, err := filemode.New(change.NewMode)
		if err != nil {
			return false, fmt.Errorf("parse mode for %s: %w", change.Path, err)
		}
		if !secretFileMode(mode) {
			continue
		}
		hash, ok := plumbing.FromHex(change.NewOID)
		if !ok {
			return false, fmt.Errorf("parse object ID for %s", change.Path)
		}
		blob, err := cache.repository.BlobObject(hash)
		if err != nil {
			return false, err
		}
		data, err := cache.dataFor(object.NewFile(change.Path, mode, blob))
		if err != nil {
			return false, err
		}
		for _, marker := range reuseMetadataMarkers {
			if bytes.Contains(data, marker) {
				return true, nil
			}
		}
	}
	return false, nil
}

func recordDetectorRun(stats *detectorStats, full bool) {
	stats.runs++
	if full {
		stats.full++
	} else {
		stats.partial++
	}
}

func addSignals(destination map[string]Signal, signals []Signal) {
	for _, signal := range signals {
		destination[signalKey(signal)] = signal
	}
}
