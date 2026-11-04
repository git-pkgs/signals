package main

import (
	"testing"

	gitlanguages "github.com/git-pkgs/languages"
	"github.com/ossf/scorecard/v5/clients"
)

func TestScorecardLanguageName(t *testing.T) {
	tests := []struct {
		language gitlanguages.Language
		want     clients.LanguageName
	}{
		{language: gitlanguages.Go, want: clients.Go},
		{language: gitlanguages.JSX, want: clients.JavaScript},
		{language: gitlanguages.TSX, want: clients.TypeScript},
		{language: gitlanguages.C2hsHaskell, want: clients.Haskell},
		{language: gitlanguages.LiterateHaskell, want: clients.Haskell},
	}
	for _, test := range tests {
		if got := scorecardLanguageName(test.language); got != test.want {
			t.Errorf("scorecardLanguageName(%s) = %q, want %q", test.language, got, test.want)
		}
	}
}

func TestFuzzingLanguageNameRejectsUnsupportedLanguage(t *testing.T) {
	if name, ok := fuzzingLanguageName(gitlanguages.Ruby); ok {
		t.Fatalf("fuzzingLanguageName(Ruby) = %q, true", name)
	}
}
