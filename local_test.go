package main

import (
	"testing"
	"testing/fstest"

	gitbrief "github.com/git-pkgs/brief"
	"github.com/git-pkgs/brief/kb"
	githistory "github.com/git-pkgs/history"
)

const (
	testRubyName          = "Ruby"
	testRubyPath          = "app.rb"
	testSemgrepConfigPath = ".semgrep.yml"
	testSemgrepName       = "Semgrep"
	testSecurityScanKind  = "security-scanning"
	testWorkflowPath      = ".github/workflows/ci.yml"
)

func TestRunBriefRefreshesOnlyCheckedTools(t *testing.T) {
	detectors := briefTestDetectors(t)
	current := emptyCommitState()
	addSignals(current.signals, []Signal{
		{Check: checkCI, Kind: "GitHub Actions", Path: testWorkflowPath},
		{Check: checkSecurityTool, Kind: testSecurityScanKind, Name: testSemgrepName, Path: testSemgrepConfigPath},
	})
	stats := &scanStats{detectors: map[string]*detectorStats{
		detectorBrief: {},
	}}
	project := fstest.MapFS{
		testSemgrepConfigPath: {Data: []byte("rules: []\n")},
	}

	detectors.runBrief(
		project,
		[]string{testWorkflowPath},
		true,
		false,
		&current,
		stats,
	)

	if _, failed := current.errors[detectorBrief]; failed {
		t.Fatalf("Brief error: %s", current.errors[detectorBrief])
	}
	for _, signal := range current.signals {
		if signal.Check == checkCI {
			t.Fatalf("removed workflow signal remains: %#v", signal)
		}
	}
	if !hasSignal(current.signals, Signal{
		Check: checkSecurityTool,
		Kind:  testSecurityScanKind,
		Name:  testSemgrepName,
		Path:  testSemgrepConfigPath,
	}) {
		t.Fatalf("unchanged Semgrep signal was removed: %#v", current.signals)
	}
}

func TestBriefLanguagesMayChangeOnlyForLanguageTransitions(t *testing.T) {
	detectors := briefTestDetectors(t)
	tests := []struct {
		name    string
		change  githistory.Change
		current []string
		want    bool
	}{
		{
			name:   "first Ruby file added",
			change: githistory.Change{Path: testRubyPath, NewOID: "1"},
			want:   true,
		},
		{
			name:    "another Ruby file added",
			change:  githistory.Change{Path: "other.rb", NewOID: "1"},
			current: []string{testRubyName},
			want:    false,
		},
		{
			name:    "Ruby file modified",
			change:  githistory.Change{Path: testRubyPath, OldOID: "1", NewOID: "2"},
			current: []string{testRubyName},
			want:    false,
		},
		{
			name: "Ruby file replaced by symlink",
			change: githistory.Change{
				Path: testRubyPath, OldOID: "1", NewOID: "2",
				OldMode: "100644", NewMode: "120000",
			},
			current: []string{testRubyName},
			want:    true,
		},
		{
			name: "Ruby symlink replaced by file",
			change: githistory.Change{
				Path: testRubyPath, OldOID: "1", NewOID: "2",
				OldMode: "120000", NewMode: "100644",
			},
			want: true,
		},
		{
			name:    "Ruby file removed",
			change:  githistory.Change{Path: testRubyPath, OldOID: "1"},
			current: []string{testRubyName},
			want:    true,
		},
		{
			name:    "workflow modified",
			change:  githistory.Change{Path: testWorkflowPath, OldOID: "1", NewOID: "2"},
			current: []string{testRubyName},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes := []githistory.Change{tt.change}
			got := detectors.briefLanguagesMayChange(
				changes,
				briefChangedPaths(changes),
				tt.current,
				false,
			)
			if got != tt.want {
				t.Fatalf("briefLanguagesMayChange() = %t, want %t", got, tt.want)
			}
		})
	}
}

func briefTestDetectors(t *testing.T) *localDetectors {
	t.Helper()
	knowledge, err := kb.Load(gitbrief.KnowledgeFS)
	if err != nil {
		t.Fatal(err)
	}
	knowledge = signalKnowledgeBase(knowledge)
	return &localDetectors{
		knowledge:   knowledge,
		briefImpact: newBriefImpactReport(knowledge),
	}
}

func hasSignal(signals map[string]Signal, wanted Signal) bool {
	_, ok := signals[signalKey(wanted)]
	return ok
}
