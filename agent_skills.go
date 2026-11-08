package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	githistory "github.com/git-pkgs/history"
	"github.com/git-pkgs/roles"
	gitskills "github.com/git-pkgs/skills"
)

const (
	agentSkillKind                = "skill"
	maxAgentSkillScriptSize int64 = 4 << 20
)

func agentSkillSignals(tree fs.FS) ([]Signal, error) {
	var signals []Signal
	err := gitskills.WalkFS(tree, ".", func(skill *gitskills.Skill, parseErr error) error {
		if parseErr != nil {
			signals = append(signals, Signal{
				Check: checkAgentSkill,
				Kind:  "invalid",
				Name:  parseErr.Error(),
			})
			return nil
		}
		if agentSkillPathExcluded(skill.Dir) {
			return nil
		}

		skillPath := path.Join(skill.Dir, gitskills.Filename)
		scriptPaths := agentSkillScriptPaths(skill.Files)
		instructionDigest := sha256.Sum256([]byte(skill.Body))
		signals = append(signals,
			Signal{
				Check: checkAgentSkill,
				Kind:  agentSkillKind,
				Name:  skill.Name,
				Value: fmt.Sprintf("files=%d; scripts=%d; warnings=%d",
					len(skill.Files), len(scriptPaths), len(skill.Warnings)),
				Path: skillPath,
			},
			Signal{
				Check: checkAgentSkill,
				Kind:  "instructions",
				Name:  skill.Name,
				Value: fmt.Sprintf("sha256:%x", instructionDigest),
				Path:  skillPath,
			},
		)
		if skill.AllowedTools != "" {
			signals = append(signals, Signal{
				Check: checkAgentSkill,
				Kind:  "allowed-tools",
				Name:  skill.Name,
				Value: skill.AllowedTools,
				Path:  skillPath,
			})
		}
		for _, scriptPath := range scriptPaths {
			fullPath := path.Join(skill.Dir, scriptPath)
			value, err := agentSkillScriptDigest(tree, fullPath)
			if err != nil {
				return err
			}
			signals = append(signals, Signal{
				Check: checkAgentSkill,
				Kind:  "script",
				Name:  skill.Name,
				Value: value,
				Path:  fullPath,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func agentSkillScriptPaths(files []string) []string {
	var scripts []string
	for _, filePath := range files {
		if strings.HasPrefix(filePath, "scripts/") {
			scripts = append(scripts, filePath)
		}
	}
	sort.Strings(scripts)
	return scripts
}

func agentSkillScriptDigest(tree fs.FS, filePath string) (string, error) {
	info, err := fs.Stat(tree, filePath)
	if err != nil {
		return "", fmt.Errorf("stat agent skill script %s: %w", filePath, err)
	}
	if info.Size() > maxAgentSkillScriptSize {
		return fmt.Sprintf("oversized; bytes=%d; mode=%#o", info.Size(), info.Mode().Perm()), nil
	}
	file, err := tree.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open agent skill script %s: %w", filePath, err)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return "", fmt.Errorf("hash agent skill script %s: %w", filePath, err)
	}
	return fmt.Sprintf("sha256:%x; mode=%#o", hash.Sum(nil), info.Mode().Perm()), nil
}

func agentSkillPathExcluded(dir string) bool {
	labels, err := roles.Match(path.Join(dir, gitskills.Filename))
	return err == nil && (labels.BundledOrDerived() || labels.Has(roles.Test) ||
		labels.Has(roles.Fixture) || labels.Has(roles.Example) || labels.Has(roles.Cache) ||
		labels.Has(roles.BuildOutput))
}

func agentSkillsAffected(changes []githistory.Change, signals map[string]Signal) bool {
	for _, change := range changes {
		if path.Base(change.Path) == gitskills.Filename {
			return true
		}
	}
	for _, signal := range signals {
		if signal.Check != checkAgentSkill || signal.Kind != agentSkillKind {
			continue
		}
		dir := path.Dir(signal.Path)
		for _, change := range changes {
			if change.Path == signal.Path || strings.HasPrefix(change.Path, dir+"/") {
				return true
			}
		}
	}
	return false
}
