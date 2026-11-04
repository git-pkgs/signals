package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	githistory "github.com/git-pkgs/history"
	gitlanguages "github.com/git-pkgs/languages"
	"github.com/git-pkgs/roles"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/ossf/scorecard/v5/clients"
)

type languageBlob struct {
	analysis gitlanguages.Analysis
}

type languagePath struct {
	include  bool
	language gitlanguages.Language
	analyze  bool
}

const languageAnalysisBytes int64 = 4 << 10

var fuzzingLanguageCandidates = gitlanguages.NewSet(
	gitlanguages.Go,
	gitlanguages.Erlang,
	gitlanguages.Haskell,
	gitlanguages.C2hsHaskell,
	gitlanguages.LiterateHaskell,
	gitlanguages.Elixir,
	gitlanguages.Gleam,
	gitlanguages.JavaScript,
	gitlanguages.JSX,
	gitlanguages.TypeScript,
	gitlanguages.TSX,
	gitlanguages.Python,
	gitlanguages.C,
	gitlanguages.CPP,
	gitlanguages.Rust,
	gitlanguages.Java,
	gitlanguages.Swift,
	gitlanguages.CSharp,
	gitlanguages.FSharp,
)

type languageInventory map[clients.LanguageName]int64

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
		if err := inventory.applyChange(change.Path, change.OldOID, change.OldMode, -1, cache); err != nil {
			return nil, err
		}
		if err := inventory.applyChange(change.Path, change.NewOID, change.NewMode, 1, cache); err != nil {
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
	if !pathInfo.include || pathInfo.language == gitlanguages.Unknown && !pathInfo.analyze {
		return false, nil
	}
	if pathInfo.language != gitlanguages.Unknown {
		if _, supported := fuzzingLanguageName(pathInfo.language); !supported {
			return false, nil
		}
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
	if !oldFile || change.OldOID == change.NewOID {
		return false, nil
	}
	return pathInfo.language == gitlanguages.Unknown && pathInfo.analyze, nil
}

func (i languageInventory) clone() languageInventory {
	clone := make(languageInventory, len(i))
	for language, count := range i {
		clone[language] = count
	}
	return clone
}

func (i languageInventory) applyChange(
	path, oid, encodedMode string,
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
	if pathInfo.language != gitlanguages.Unknown {
		return i.applyDetectedLanguage(pathInfo.language, direction)
	}
	if !pathInfo.analyze {
		return nil
	}
	hash, ok := plumbing.FromHex(oid)
	if !ok {
		return fmt.Errorf("parse object ID for %s", path)
	}
	blob, err := cache.languageBlobOID(hash)
	if err != nil {
		return fmt.Errorf("analyze %s language: %w", path, err)
	}
	return i.applyLanguage(path, blob, direction)
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
	if pathInfo.language != gitlanguages.Unknown {
		return i.applyDetectedLanguage(pathInfo.language, direction)
	}
	if !pathInfo.analyze {
		return nil
	}
	blob, err := cache.languageBlob(file)
	if err != nil {
		return fmt.Errorf("analyze %s language: %w", path, err)
	}
	return i.applyLanguage(path, blob, direction)
}

func languageFileMode(mode filemode.FileMode) bool {
	return mode == filemode.Regular || mode == filemode.Deprecated || mode == filemode.Executable
}

func (i languageInventory) applyLanguage(path string, blob languageBlob, direction int64) error {
	result := blob.analysis.Detect(path)
	if result.Language == gitlanguages.Unknown {
		return nil
	}
	return i.applyDetectedLanguage(result.Language, direction)
}

func (i languageInventory) applyDetectedLanguage(
	language gitlanguages.Language,
	direction int64,
) error {
	name, supported := fuzzingLanguageName(language)
	if !supported {
		return nil
	}
	next := i[name] + direction
	if next < 0 {
		return fmt.Errorf("language byte count became negative for %s", name)
	}
	if next == 0 {
		delete(i, name)
	} else {
		i[name] = next
	}
	return nil
}

func fuzzingLanguageName(language gitlanguages.Language) (clients.LanguageName, bool) {
	name := scorecardLanguageName(language)
	switch name {
	case clients.Go, clients.Erlang, clients.Haskell, clients.Elixir, clients.Gleam,
		clients.JavaScript, clients.TypeScript, clients.Python, clients.C, clients.Cpp,
		clients.Rust, clients.Java, clients.Swift, clients.CSharp, clients.FSharp:
		return name, true
	default:
		return "", false
	}
}

func scorecardLanguageName(language gitlanguages.Language) clients.LanguageName {
	switch language {
	case gitlanguages.JSX:
		return clients.JavaScript
	case gitlanguages.TSX:
		return clients.TypeScript
	case gitlanguages.C2hsHaskell, gitlanguages.LiterateHaskell:
		return clients.Haskell
	default:
		return clients.LanguageName(strings.ToLower(language.String()))
	}
}

func (c *blobCache) languageBlob(file *object.File) (languageBlob, error) {
	key := file.Hash.String()
	if blob, ok := c.languageBlobs[key]; ok {
		return blob, nil
	}
	data, cached := c.data[key]
	complete := true
	if !cached {
		reader, err := file.Reader()
		if err != nil {
			return languageBlob{}, err
		}
		limit := min(file.Size, languageAnalysisBytes)
		var readErr error
		data, readErr = io.ReadAll(io.LimitReader(reader, limit))
		err = errors.Join(readErr, reader.Close())
		if err != nil {
			return languageBlob{}, err
		}
		complete = int64(len(data)) == file.Size
	}
	var analysis gitlanguages.Analysis
	gitlanguages.Analyze(data, complete, &analysis)
	blob := languageBlob{analysis: analysis}
	c.languageBlobs[key] = blob
	return blob, nil
}

func (c *blobCache) languageBlobOID(hash plumbing.Hash) (languageBlob, error) {
	key := hash.String()
	if blob, ok := c.languageBlobs[key]; ok {
		return blob, nil
	}
	objectBlob, err := c.repository.BlobObject(hash)
	if err != nil {
		return languageBlob{}, err
	}
	return c.languageBlob(object.NewFile("", filemode.Regular, objectBlob))
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
		analyze:  !context.Candidates.Intersect(fuzzingLanguageCandidates).Empty(),
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

func includeFuzzingPath(path string) bool {
	include, err := includeLanguagePath(path)
	return err == nil && include
}

func (i languageInventory) scorecard() []clients.Language {
	names := make([]clients.LanguageName, 0, len(i))
	for name := range i {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool { return names[left] < names[right] })
	result := make([]clients.Language, 0, len(names))
	for _, name := range names {
		result = append(result, clients.Language{Name: name, NumLines: 1})
	}
	return result
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
