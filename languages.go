package main

import (
	"fmt"

	githistory "github.com/git-pkgs/history"
	gitlanguages "github.com/git-pkgs/languages"
	"github.com/git-pkgs/roles"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
)

type languagePath struct {
	include  bool
	language gitlanguages.Language
}

type languageInventory map[gitlanguages.Language]int64

func languageInventoryForCommit(
	parent languageInventory,
	commit *object.Commit,
	changes []githistory.Change,
	forceFull bool,
	cache *blobCache,
) (languageInventory, error) {
	if forceFull {
		return fullLanguageInventory(commit, cache)
	}
	return updateLanguageInventory(parent, changes, cache)
}

func fullLanguageInventory(commit *object.Commit, cache *blobCache) (languageInventory, error) {
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read commit tree for languages: %w", err)
	}
	inventory := make(languageInventory)
	iter := tree.Files()
	defer iter.Close()
	if err := iter.ForEach(func(file *object.File) error {
		return inventory.applyFile(file.Name, file, 1, cache)
	}); err != nil {
		return nil, err
	}
	return inventory, nil
}

func updateLanguageInventory(
	parent languageInventory,
	changes []githistory.Change,
	cache *blobCache,
) (languageInventory, error) {
	inventory := parent
	cloned := false
	for _, change := range changes {
		affectsInventory, err := languageChangeAffectsInventory(change, cache)
		if err != nil {
			return nil, err
		}
		if !affectsInventory {
			continue
		}
		if !cloned {
			inventory = parent.clone()
			cloned = true
		}
		if err := inventory.applyChange(change.Path, change.OldMode, -1, cache); err != nil {
			return nil, err
		}
		if err := inventory.applyChange(change.Path, change.NewMode, 1, cache); err != nil {
			return nil, err
		}
	}
	return inventory, nil
}

func languageChangeAffectsInventory(change githistory.Change, cache *blobCache) (bool, error) {
	pathInfo, err := cache.languagePath(change.Path)
	if err != nil {
		return false, err
	}
	if !pathInfo.include || pathInfo.language == gitlanguages.Unknown {
		return false, nil
	}
	oldMode, err := filemode.New(change.OldMode)
	if err != nil {
		return false, fmt.Errorf("parse old mode for %s: %w", change.Path, err)
	}
	newMode, err := filemode.New(change.NewMode)
	if err != nil {
		return false, fmt.Errorf("parse new mode for %s: %w", change.Path, err)
	}
	oldFile, newFile := languageFileMode(oldMode), languageFileMode(newMode)
	if oldFile != newFile {
		return true, nil
	}
	return false, nil
}

func (i languageInventory) clone() languageInventory {
	clone := make(languageInventory, len(i))
	for language, count := range i {
		clone[language] = count
	}
	return clone
}

func (i languageInventory) applyChange(
	path, encodedMode string,
	direction int64,
	cache *blobCache,
) error {
	mode, err := filemode.New(encodedMode)
	if err != nil {
		return fmt.Errorf("parse mode for %s: %w", path, err)
	}
	if !languageFileMode(mode) {
		return nil
	}
	pathInfo, err := cache.languagePath(path)
	if err != nil {
		return err
	}
	if !pathInfo.include {
		return nil
	}
	return i.applyDetectedLanguage(pathInfo.language, direction)
}

func (i languageInventory) applyFile(path string, file *object.File, direction int64, cache *blobCache) error {
	if !languageFileMode(file.Mode) {
		return nil
	}
	pathInfo, err := cache.languagePath(path)
	if err != nil {
		return err
	}
	if !pathInfo.include {
		return nil
	}
	return i.applyDetectedLanguage(pathInfo.language, direction)
}

func languageFileMode(mode filemode.FileMode) bool {
	return mode == filemode.Regular || mode == filemode.Deprecated || mode == filemode.Executable
}

func (i languageInventory) applyDetectedLanguage(
	language gitlanguages.Language,
	direction int64,
) error {
	if language == gitlanguages.Unknown {
		return nil
	}
	next := i[language] + direction
	if next < 0 {
		return fmt.Errorf("language byte count became negative for %s", language)
	}
	if next == 0 {
		delete(i, language)
	} else {
		i[language] = next
	}
	return nil
}

func (c *blobCache) languagePath(path string) (languagePath, error) {
	if result, ok := c.languagePaths[path]; ok {
		return result, nil
	}
	include, err := includeLanguagePath(path)
	if err != nil {
		return languagePath{}, err
	}
	context := gitlanguages.AnalyzePath(path)
	result := languagePath{
		include:  include,
		language: context.Result().Language,
	}
	c.languagePaths[path] = result
	return result, nil
}

func includeLanguagePath(path string) (bool, error) {
	set, err := roles.Match(path)
	if err != nil {
		return false, fmt.Errorf("classify %s: %w", path, err)
	}
	return !set.BundledOrDerived() && !set.Has(roles.Generated), nil
}

func (i languageInventory) sameLanguages(other languageInventory) bool {
	if len(i) != len(other) {
		return false
	}
	for language := range i {
		if _, ok := other[language]; !ok {
			return false
		}
	}
	return true
}
