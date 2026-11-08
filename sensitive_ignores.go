package main

import (
	"io/fs"
	"path"
	"sort"
	"strconv"

	"github.com/git-pkgs/gitignore"
	githistory "github.com/git-pkgs/history"
	"github.com/git-pkgs/roles"
)

const (
	maxSensitiveIgnoreScopes   = 10_000
	maxSensitiveIgnoreFileSize = 1 << 20
	sensitiveIgnoreCredential  = "credential"
	sensitiveIgnoreDatabase    = "database"
	sensitiveIgnoreEnvironment = "environment"
	sensitiveIgnorePrivateKey  = "private-key"
	sensitiveIgnoreSecret      = "secret"
	sensitiveIgnoreState       = "state"
	sensitiveIgnoreCoverage    = "coverage"
)

type sensitiveIgnoreCandidate struct {
	kind string
	path string
}

var sensitiveIgnoreCandidates = []sensitiveIgnoreCandidate{
	{kind: sensitiveIgnoreCredential, path: ".aws/credentials"},
	{kind: sensitiveIgnoreCredential, path: ".docker/config.json"},
	{kind: sensitiveIgnoreCredential, path: ".gem/credentials"},
	{kind: sensitiveIgnoreCredential, path: ".netrc"},
	{kind: sensitiveIgnoreCredential, path: ".npmrc"},
	{kind: sensitiveIgnoreCredential, path: ".pypirc"},
	{kind: sensitiveIgnoreCredential, path: "application_default_credentials.json"},
	{kind: sensitiveIgnoreCredential, path: "credentials.json"},
	{kind: sensitiveIgnoreCredential, path: "credentials.yaml"},
	{kind: sensitiveIgnoreCredential, path: "credentials.yml"},
	{kind: sensitiveIgnoreDatabase, path: "backup.sql"},
	{kind: sensitiveIgnoreDatabase, path: "database.dump"},
	{kind: sensitiveIgnoreDatabase, path: "database.sql"},
	{kind: sensitiveIgnoreEnvironment, path: ".env"},
	{kind: sensitiveIgnoreEnvironment, path: ".env.local"},
	{kind: sensitiveIgnoreEnvironment, path: ".env.production"},
	{kind: sensitiveIgnoreEnvironment, path: ".envrc"},
	{kind: sensitiveIgnorePrivateKey, path: "private.key"},
	{kind: sensitiveIgnorePrivateKey, path: "private.pem"},
	{kind: sensitiveIgnorePrivateKey, path: "id_rsa"},
	{kind: sensitiveIgnorePrivateKey, path: "id_ed25519"},
	{kind: sensitiveIgnorePrivateKey, path: "config/master.key"},
	{kind: sensitiveIgnorePrivateKey, path: "certificate.p12"},
	{kind: sensitiveIgnorePrivateKey, path: "certificate.pfx"},
	{kind: sensitiveIgnoreSecret, path: "config/secrets.yml"},
	{kind: sensitiveIgnoreSecret, path: "secrets.json"},
	{kind: sensitiveIgnoreSecret, path: "secrets.yaml"},
	{kind: sensitiveIgnoreSecret, path: "secrets.yml"},
	{kind: sensitiveIgnoreState, path: "terraform.tfstate"},
	{kind: sensitiveIgnoreState, path: "terraform.tfstate.backup"},
	{kind: sensitiveIgnoreState, path: ".terraform/terraform.tfstate"},
}

func sensitiveIgnoreSignals(tree fs.FS) ([]Signal, error) {
	matcher, scopeNames, signals, truncatedScopes, err := loadSensitiveIgnorePatterns(tree)
	if err != nil {
		return nil, err
	}
	signals = append(signals, matchSensitiveIgnoreCandidates(matcher, scopeNames)...)
	for _, patternErr := range matcher.Errors() {
		signals = append(signals, Signal{
			Check: checkSensitiveIgnore,
			Kind:  "invalid-pattern",
			Name:  patternErr.Pattern,
			Value: patternErr.Message,
			Path:  patternErr.Source,
			Line:  uint(patternErr.Line),
		})
	}
	if truncatedScopes {
		signals = append(signals, Signal{
			Check: checkSensitiveIgnore,
			Kind:  sensitiveIgnoreCoverage,
			Name:  "scopes-truncated",
			Value: "limit=" + strconv.Itoa(maxSensitiveIgnoreScopes),
		})
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func loadSensitiveIgnorePatterns(tree fs.FS) (*gitignore.Matcher, []string, []Signal, bool, error) {
	matcher := gitignore.New("")
	scopes := map[string]bool{"": true}
	var signals []Signal
	truncatedScopes := false
	err := fs.WalkDir(tree, ".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filePath != "." && sensitiveIgnorePathExcluded(filePath) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Name() != ".gitignore" || sensitiveIgnorePathExcluded(filePath) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxSensitiveIgnoreFileSize {
			signals = append(signals, Signal{
				Check: checkSensitiveIgnore,
				Kind:  sensitiveIgnoreCoverage,
				Name:  "oversized-ignore-file",
				Value: strconv.FormatInt(info.Size(), 10),
				Path:  filePath,
			})
			return nil
		}
		data, err := fs.ReadFile(tree, filePath)
		if err != nil {
			return err
		}
		dir := path.Dir(filePath)
		if dir == "." {
			dir = ""
		}
		matcher.AddPatternsWithSource(data, dir, filePath)
		if len(scopes) < maxSensitiveIgnoreScopes {
			scopes[dir] = true
		} else if !scopes[dir] {
			truncatedScopes = true
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, false, err
	}

	scopeNames := make([]string, 0, len(scopes))
	for dir := range scopes {
		scopeNames = append(scopeNames, dir)
	}
	sort.Strings(scopeNames)
	return matcher, scopeNames, signals, truncatedScopes, nil
}

func matchSensitiveIgnoreCandidates(matcher *gitignore.Matcher, scopeNames []string) []Signal {
	seen := make(map[string]bool)
	var signals []Signal
	for _, dir := range scopeNames {
		for _, candidate := range sensitiveIgnoreCandidates {
			target := path.Join(dir, candidate.path)
			result := matcher.MatchDetail(target)
			if !result.Ignored {
				continue
			}
			key := result.Source + "\x00" + strconv.Itoa(result.Line) + "\x00" + candidate.kind
			if seen[key] {
				continue
			}
			seen[key] = true
			signals = append(signals, Signal{
				Check: checkSensitiveIgnore,
				Kind:  candidate.kind,
				Name:  target,
				Value: result.Pattern,
				Path:  result.Source,
				Line:  uint(result.Line),
			})
		}
	}
	return signals
}

func sensitiveIgnorePathExcluded(filePath string) bool {
	labels, err := roles.Match(filePath)
	return err == nil && (labels.BundledOrDerived() || labels.Has(roles.Test) ||
		labels.Has(roles.Fixture) || labels.Has(roles.Example) || labels.Has(roles.Cache) ||
		labels.Has(roles.BuildOutput))
}

func sensitiveIgnoresAffected(changes []githistory.Change) bool {
	for _, change := range changes {
		if path.Base(change.Path) == ".gitignore" && !sensitiveIgnorePathExcluded(change.Path) {
			return true
		}
	}
	return false
}
