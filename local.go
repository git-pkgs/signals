package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
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
	checkThreatSurface     = "Threat-Surface"

	detectorBrief           = "Brief"
	detectorAgentSkills     = "Agent-Skills"
	detectorRepositoryFiles = "Repository-Files"
	detectorSensitiveIgnore = "Sensitive-Ignores"
	detectorWorkflows       = "Workflows"

	maxSecretBlobSize   = 1 << 20
	reuseMarkerReadSize = 32 * 1024
)

var localDetectorNames = []string{
	detectorAgentSkills,
	detectorBrief,
	checkDependencyUpdateConfig,
	detectorPackages,
	detectorPackageManagers,
	detectorRepositoryFiles,
	detectorSensitiveIgnore,
	detectorWorkflows,
	checkSecret,
	checkREUSE,
}

var reuseMetadataMarkers = [...][]byte{
	[]byte("SPDX-License-Identifier:"),
	[]byte("SPDX-FileCopyrightText:"),
	[]byte("SPDX-FileContributor:"),
}

type localDetectors struct {
	repo                *githistory.Repo
	knowledge           *kb.KnowledgeBase
	briefImpact         *gitbrief.Report
	secretScanner       *scanner.Scanner
	secretCache         map[secretCacheKey][]Signal
	packageCache        map[packageCacheKey][]Signal
	repositoryFileCache map[repositoryFileCacheKey][]Signal
	workflowCache       map[workflowCacheKey][]Signal
	packageManagers     *packageManagerDetector
	repositoryPaths     *repositoryPathRules
	shell               *shellAnalyzer
	reuseMarkers        map[plumbing.Hash]bool
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
	packageManagers, err := newPackageManagerDetector()
	if err != nil {
		return nil, err
	}
	secretScanner, err := scanner.New(ctx, scanner.Options{})
	if err != nil {
		return nil, fmt.Errorf("create secret scanner: %w", err)
	}
	repositoryPaths := newRepositoryPathRules(knowledge)
	knowledge = signalKnowledgeBase(knowledge)
	detectors := &localDetectors{
		repo:                repo,
		knowledge:           knowledge,
		secretScanner:       secretScanner,
		secretCache:         make(map[secretCacheKey][]Signal),
		packageCache:        make(map[packageCacheKey][]Signal),
		repositoryFileCache: make(map[repositoryFileCacheKey][]Signal),
		workflowCache:       make(map[workflowCacheKey][]Signal),
		packageManagers:     packageManagers,
		repositoryPaths:     repositoryPaths,
		shell:               newShellAnalyzer(packageManagers.definitions),
		reuseMarkers:        make(map[plumbing.Hash]bool),
	}
	detectors.briefImpact = newBriefImpactReport(knowledge)
	return detectors, nil
}

func signalKnowledgeBase(source *kb.KnowledgeBase) *kb.KnowledgeBase {
	filtered := &kb.KnowledgeBase{
		ByName:         make(map[string]*kb.ToolDef),
		ByCategory:     make(map[string][]*kb.ToolDef),
		Ecosystems:     make(map[string][]*kb.ToolDef),
		ManifestFiles:  append([]string(nil), source.ManifestFiles...),
		Threats:        source.Threats,
		ThreatMappings: append([]kb.ThreatMapping(nil), source.ThreatMappings...),
	}
	for _, tool := range source.Tools {
		_, _, _, selected := briefSignalType(tool.Tool.Name, tool.Tool.Category, taxonomyFromTool(tool))
		if tool.Tool.Category != "language" && !selected && !briefThreatContributor(tool, source.ThreatMappings) {
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
	stats *scanStats,
) (commitState, error) {
	current := cloneCommitState(parent)
	briefPaths := briefChangedPaths(changes)
	briefFull := forceFull || parent.errors[detectorBrief] != "" ||
		d.briefLanguagesMayChange(changes, briefPaths, parent.briefLanguages, languagesChanged)
	briefRun := briefFull || len(briefPaths) > 0
	agentSkillFull := forceFull || parent.errors[detectorAgentSkills] != ""
	agentSkillRun := agentSkillFull || agentSkillsAffected(changes, parent.signals)
	dependencyUpdateFull := forceFull || parent.errors[checkDependencyUpdateConfig] != ""
	dependencyUpdateRun := dependencyUpdateFull || dependencyUpdateConfigAffected(changedPaths(changes))
	packageFull := forceFull || parent.errors[detectorPackages] != ""
	packageRun := packageFull || packagesAffected(changes)
	repositoryFileFull := forceFull || parent.errors[detectorRepositoryFiles] != ""
	repositoryFileRun := repositoryFileFull || len(changes) > 0
	sensitiveIgnoreFull := forceFull || parent.errors[detectorSensitiveIgnore] != ""
	sensitiveIgnoreRun := sensitiveIgnoreFull || sensitiveIgnoresAffected(changes)
	workflowAffected := workflowsAffected(changes)
	workflowError := parent.errors[detectorWorkflows]
	workflowFull := forceFull || workflowError != "" &&
		(workflowAffected || !strings.HasPrefix(workflowError, "parse workflow "))
	workflowRun := workflowFull || workflowAffected
	managerDirectories, managerImpactErr := d.packageManagers.directoriesForChanges(changes)
	managerFull := forceFull || parent.errors[detectorPackageManagers] != ""
	managerRun := managerFull || managerImpactErr != nil || len(managerDirectories) > 0
	secretFull := forceFull || parent.errors[checkSecret] != ""
	reuseFull := forceFull || parent.errors[checkREUSE] != "" || reuseMetadataChanged(changes)
	if !reuseFull && !parent.reuseActive {
		var err error
		reuseFull, err = d.reuseChangeMayActivate(changes)
		if err != nil {
			return commitState{}, err
		}
	}
	reuseRun := reuseFull || parent.reuseActive && len(changes) > 0

	var tree fs.FS
	if anyDetectorRuns(agentSkillRun, briefRun, dependencyUpdateRun, packageRun, repositoryFileRun, sensitiveIgnoreRun, workflowRun, managerRun, reuseRun) {
		var err error
		tree, err = d.repo.TreeFS(commit.Hash)
		if err != nil {
			return commitState{}, err
		}
	}

	d.runAgentSkills(tree, agentSkillRun, &current, stats)
	d.runBrief(tree, briefPaths, briefRun, briefFull, &current, stats)
	d.runDependencyUpdateConfigs(tree, dependencyUpdateRun, dependencyUpdateFull, &current, stats)
	d.runPackages(tree, changes, packageRun, packageFull, &current, stats)
	d.runRepositoryFiles(ctx, tree, changes, repositoryFileRun, repositoryFileFull, &current, stats)
	d.runSensitiveIgnores(tree, sensitiveIgnoreRun, &current, stats)
	d.runWorkflows(tree, changes, workflowRun, workflowFull, &current, stats)
	d.runPackageManagers(
		tree,
		managerDirectories,
		managerImpactErr,
		managerRun,
		managerFull,
		&current,
		stats,
	)
	d.runSecrets(ctx, commit, changes, secretFull, &current, stats)
	d.runREUSE(tree, changes, reuseRun, reuseFull, &current, stats)
	return current, nil
}

func (d *localDetectors) runAgentSkills(
	tree fs.FS,
	run bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorAgentSkills]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, true)
	started := time.Now()
	signals, err := agentSkillSignals(tree)
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorAgentSkills] = err.Error()
		return
	}
	delete(current.errors, detectorAgentSkills)
	removeCheckSignals(current.signals, checkAgentSkill)
	addSignals(current.signals, signals)
}

func (d *localDetectors) runSensitiveIgnores(
	tree fs.FS,
	run bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorSensitiveIgnore]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, true)
	started := time.Now()
	signals, err := sensitiveIgnoreSignals(tree)
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorSensitiveIgnore] = err.Error()
		return
	}
	delete(current.errors, detectorSensitiveIgnore)
	removeCheckSignals(current.signals, checkSensitiveIgnore)
	addSignals(current.signals, signals)
}

func anyDetectorRuns(runs ...bool) bool {
	for _, run := range runs {
		if run {
			return true
		}
	}
	return false
}

func (d *localDetectors) runPackageManagers(
	tree fs.FS,
	directories []string,
	impactErr error,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorPackageManagers]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()
	if impactErr != nil {
		detectorStats.duration += time.Since(started)
		current.errors[detectorPackageManagers] = impactErr.Error()
		return
	}

	var err error
	if forceFull {
		directories, err = d.packageManagers.directoriesForTree(tree)
	}
	var signals []Signal
	if err == nil {
		signals, err = d.packageManagers.signals(tree, directories)
	}
	if err == nil {
		err = d.packageManagers.removeSignals(current.signals, directories, forceFull)
	}
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorPackageManagers] = err.Error()
		return
	}

	delete(current.errors, detectorPackageManagers)
	addSignals(current.signals, signals)
}

func (d *localDetectors) runPackages(
	tree fs.FS,
	changes []githistory.Change,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorPackages]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()

	var signals []Signal
	var paths []string
	var err error
	if forceFull {
		signals, err = allPackageSignals(tree)
	} else {
		signals, paths, err = packageSignalsForChanges(tree, changes, d.packageCache)
	}
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorPackages] = err.Error()
		return
	}

	delete(current.errors, detectorPackages)
	if forceFull {
		removePackageSignals(current.signals, nil)
	} else {
		pathSet := make(map[string]bool, len(paths))
		for _, path := range paths {
			pathSet[path] = true
		}
		removePackageSignals(current.signals, pathSet)
	}
	addSignals(current.signals, signals)
}

func (d *localDetectors) runDependencyUpdateConfigs(
	tree fs.FS,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[checkDependencyUpdateConfig]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()
	signals, err := dependencyUpdateConfigSignals(tree)
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[checkDependencyUpdateConfig] = err.Error()
		return
	}
	delete(current.errors, checkDependencyUpdateConfig)
	removeCheckSignals(current.signals, checkDependencyUpdateConfig)
	removeCheckSignals(current.signals, checkDependencyUpdateTool)
	addSignals(current.signals, signals)
}

func (d *localDetectors) runBrief(
	tree fs.FS,
	changedPaths []string,
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
	var signals []Signal
	var checked []briefdetect.ToolRef
	var languages []string
	var err error
	if forceFull {
		signals, languages, err = d.briefSignals(tree)
	} else {
		signals, checked, err = d.briefChangedSignals(tree, changedPaths, current.briefLanguages)
	}
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorBrief] = err.Error()
		return
	}
	delete(current.errors, detectorBrief)
	if forceFull {
		removeBriefSignals(current.signals)
		current.briefLanguages = languages
	} else {
		d.removeBriefToolSignals(current.signals, checked)
	}
	addSignals(current.signals, signals)
}

func (d *localDetectors) briefSignals(tree fs.FS) ([]Signal, []string, error) {
	engine := briefdetect.NewFS(d.knowledge, tree)
	report, err := engine.Run()
	if err != nil {
		return nil, nil, err
	}
	languages := make([]string, 0, len(report.Languages))
	for _, language := range report.Languages {
		languages = append(languages, language.Name)
	}
	sort.Strings(languages)
	signals := append(briefToolSignals(report.Tools), briefThreatSignals(report, engine.ThreatModel(report))...)
	sortSignals(signals)
	return deduplicateSignals(signals), languages, nil
}

func (d *localDetectors) briefChangedSignals(
	tree fs.FS,
	changedPaths, languages []string,
) ([]Signal, []briefdetect.ToolRef, error) {
	engine := briefdetect.NewFS(d.knowledge, tree)
	scan, err := engine.RunTools(briefdetect.ToolScanOptions{
		ChangedFiles: changedPaths,
		Languages:    languages,
	})
	if err != nil {
		return nil, nil, err
	}
	report := &gitbrief.Report{Tools: scan.Tools}
	signals := append(briefToolSignals(scan.Tools), briefThreatSignals(report, engine.ThreatModel(report))...)
	sortSignals(signals)
	return deduplicateSignals(signals), scan.Checked, nil
}

func briefThreatSignals(report *gitbrief.Report, threats *gitbrief.ThreatReport) []Signal {
	paths := briefDetectionPaths(report)
	var signals []Signal
	for _, threat := range threats.Threats {
		for _, tool := range threat.IntroducedBy {
			toolPaths := paths[tool]
			if len(toolPaths) == 0 {
				signals = append(signals, Signal{
					Check: checkThreatSurface,
					Kind:  threat.ID,
					Name:  tool,
					Value: threat.CWE,
				})
				continue
			}
			for _, detectedPath := range toolPaths {
				signals = append(signals, Signal{
					Check: checkThreatSurface,
					Kind:  threat.ID,
					Name:  tool,
					Value: threat.CWE,
					Path:  detectedPath,
				})
			}
		}
	}
	return signals
}

func briefDetectionPaths(report *gitbrief.Report) map[string][]string {
	detections := append([]gitbrief.Detection(nil), report.Languages...)
	detections = append(detections, report.PackageManagers...)
	for _, tools := range report.Tools {
		detections = append(detections, tools...)
	}
	paths := make(map[string][]string)
	for _, detection := range detections {
		paths[detection.Name] = append(paths[detection.Name], detection.ConfigFiles...)
		if detection.Lockfile != "" {
			paths[detection.Name] = append(paths[detection.Name], detection.Lockfile)
		}
	}
	for name := range paths {
		sort.Strings(paths[name])
		paths[name] = slices.Compact(paths[name])
	}
	return paths
}

func briefThreatContributor(tool *kb.ToolDef, mappings []kb.ThreatMapping) bool {
	if len(tool.Security.Threats) > 0 {
		return true
	}
	tags := make(map[string]bool)
	for _, tag := range tool.Taxonomy.Tags() {
		tags[tag] = true
	}
	for _, mapping := range mappings {
		if briefThreatMappingMatches(tags, mapping.Match) {
			return true
		}
	}
	return false
}

func briefThreatMappingMatches(tags map[string]bool, required []string) bool {
	if len(required) == 0 {
		return false
	}
	for _, tag := range required {
		if !tags[tag] {
			return false
		}
	}
	return true
}

func briefToolSignals(tools map[string][]gitbrief.Detection) []Signal {
	var signals []Signal
	for _, detections := range tools {
		for _, detection := range detections {
			check, kind, name, ok := briefSignalType(detection.Name, detection.Category, detection.Taxonomy)
			if !ok {
				continue
			}
			paths := append([]string(nil), detection.ConfigFiles...)
			if detection.Lockfile != "" {
				paths = append(paths, detection.Lockfile)
			}
			if check == checkSecurityTool && len(paths) == 0 && detection.Confidence != gitbrief.ConfidenceHigh {
				continue
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
	return deduplicateSignals(signals)
}

func briefChangedPaths(changes []githistory.Change) []string {
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		labels, err := roles.Match(change.Path)
		if err == nil && (labels.Has(roles.Vendor) || labels.Has(roles.Fixture) ||
			labels.Has(roles.Cache) || labels.Has(roles.BuildOutput)) {
			continue
		}
		paths = append(paths, change.Path)
	}
	return paths
}

func (d *localDetectors) briefLanguagesMayChange(
	changes []githistory.Change,
	paths, current []string,
	languagesChanged bool,
) bool {
	if len(paths) == 0 {
		return false
	}
	filtered := briefdetect.FilterByChangedFiles(d.briefImpact, d.knowledge, paths)
	if len(filtered.Manifests) > 0 {
		return true
	}
	if len(filtered.Languages) == 0 {
		return false
	}
	if languagesChanged {
		return true
	}

	known := make(map[string]bool, len(current))
	for _, language := range current {
		known[language] = true
	}
	included := make(map[string]bool, len(paths))
	for _, changedPath := range paths {
		included[changedPath] = true
	}
	for _, change := range changes {
		if !included[change.Path] {
			continue
		}
		added, removed := briefFileTransition(change)
		if !added && !removed {
			continue
		}
		matched := briefdetect.FilterByChangedFiles(d.briefImpact, d.knowledge, []string{change.Path})
		for _, language := range matched.Languages {
			if (added && !known[language.Name]) || (removed && known[language.Name]) {
				return true
			}
		}
	}
	return false
}

func briefFileTransition(change githistory.Change) (added, removed bool) {
	oldFile, oldModeKnown := encodedLanguageFileMode(change.OldMode)
	newFile, newModeKnown := encodedLanguageFileMode(change.NewMode)
	if oldModeKnown && newModeKnown {
		return !oldFile && newFile, oldFile && !newFile
	}
	return nonzeroOID(change.OldOID) == "" && nonzeroOID(change.NewOID) != "",
		nonzeroOID(change.OldOID) != "" && nonzeroOID(change.NewOID) == ""
}

func encodedLanguageFileMode(encoded string) (bool, bool) {
	if encoded == "" {
		return false, false
	}
	mode, err := filemode.New(encoded)
	if err != nil {
		return false, false
	}
	return languageFileMode(mode), true
}

func newBriefImpactReport(knowledge *kb.KnowledgeBase) *gitbrief.Report {
	report := &gitbrief.Report{Tools: make(map[string][]gitbrief.Detection)}
	for _, manifest := range knowledge.ManifestFiles {
		report.Manifests = append(report.Manifests, gitbrief.ManifestInfo{Path: manifest})
	}
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
		kind = signalKindTool
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
		case checkBuild, checkCI, checkPreCommit, checkSecretsManagement, checkSecurityTool, checkThreatSurface:
			delete(signals, key)
		}
	}
}

func (d *localDetectors) removeBriefToolSignals(signals map[string]Signal, checked []briefdetect.ToolRef) {
	selected := make(map[string]bool, len(checked))
	checkedNames := make(map[string]bool, len(checked))
	for _, ref := range checked {
		checkedNames[ref.Name] = true
		tool := d.knowledge.ByName[ref.Name]
		if tool == nil || tool.Tool.Category != ref.Category {
			continue
		}
		check, kind, name, ok := briefSignalType(ref.Name, ref.Category, taxonomyFromTool(tool))
		if ok {
			selected[briefSignalIdentity(check, kind, name)] = true
		}
	}
	for key, signal := range signals {
		if signal.Check == checkThreatSurface && checkedNames[signal.Name] {
			delete(signals, key)
			continue
		}
		if selected[briefSignalIdentity(signal.Check, signal.Kind, signal.Name)] {
			delete(signals, key)
		}
	}
}

func briefSignalIdentity(check, kind, name string) string {
	return check + "\x00" + kind + "\x00" + name
}

func (d *localDetectors) runSecrets(
	ctx context.Context,
	commit *object.Commit,
	changes []githistory.Change,
	forceFull bool,
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
	signals, paths, err := d.secretSignals(ctx, commit, changes, forceFull)
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
			found, err := d.scanSecretFile(ctx, file)
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
		found, err := d.scanSecretFile(ctx, file)
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
) ([]Signal, error) {
	key := secretCacheKey{oid: file.Hash.String(), path: file.Name}
	if signals, ok := d.secretCache[key]; ok {
		return signals, nil
	}
	if file.Size > maxSecretBlobSize {
		d.secretCache[key] = nil
		return nil, nil
	}
	data, err := readBlob(file)
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

func readBlob(file *object.File) ([]byte, error) {
	reader, err := file.Reader()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(reader)
	return data, errors.Join(readErr, reader.Close())
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

func (d *localDetectors) reuseChangeMayActivate(changes []githistory.Change) (bool, error) {
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
		matched, cached := d.reuseMarkers[hash]
		if !cached {
			blob, err := d.repo.Repository().BlobObject(hash)
			if err != nil {
				return false, err
			}
			matched, err = blobContainsAny(blob, reuseMetadataMarkers[:])
			if err != nil {
				return false, err
			}
			d.reuseMarkers[hash] = matched
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func blobContainsAny(blob *object.Blob, markers [][]byte) (bool, error) {
	reader, err := blob.Reader()
	if err != nil {
		return false, err
	}
	matched, readErr := readerContainsAny(reader, markers)
	return matched, errors.Join(readErr, reader.Close())
}

func readerContainsAny(reader io.Reader, markers [][]byte) (bool, error) {
	maxMarkerSize := 0
	for _, marker := range markers {
		maxMarkerSize = max(maxMarkerSize, len(marker))
	}
	if maxMarkerSize == 0 {
		return false, nil
	}

	overlapSize := maxMarkerSize - 1
	buffer := make([]byte, reuseMarkerReadSize+overlapSize)
	retained := 0
	for {
		read, err := reader.Read(buffer[retained : retained+reuseMarkerReadSize])
		chunk := buffer[:retained+read]
		matched := false
		for _, marker := range markers {
			if bytes.Contains(chunk, marker) {
				matched = true
				break
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return matched, nil
			}
			return false, err
		}
		if matched {
			return true, nil
		}
		retained = min(overlapSize, len(chunk))
		copy(buffer[:retained], chunk[len(chunk)-retained:])
	}
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
