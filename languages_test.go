package main

import (
	"testing"

	gitlanguages "github.com/git-pkgs/languages"
)

func TestLanguageInventoryTracksEveryDetectedLanguage(t *testing.T) {
	inventory := make(languageInventory)
	if err := inventory.applyDetectedLanguage(gitlanguages.Ruby, 1); err != nil {
		t.Fatal(err)
	}
	if inventory[gitlanguages.Ruby] != 1 {
		t.Fatalf("Ruby count = %d", inventory[gitlanguages.Ruby])
	}
}

func TestLanguagePathUsesCache(t *testing.T) {
	cache := &blobCache{languagePaths: make(map[string]languagePath)}
	const path = "src/fuzz_test.go"
	info, err := cache.languagePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.include || info.language != gitlanguages.Go {
		t.Fatalf("languagePath(%q) = %#v", path, info)
	}
	info.include = false
	cache.languagePaths[path] = info
	cached, err := cache.languagePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if cached.include {
		t.Fatalf("cached languagePath(%q) = %#v", path, cached)
	}
}
