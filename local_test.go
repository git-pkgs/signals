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
	testSecurityCategory  = "security"
	testSecurityScanKind  = "security-scanning"
	testTemplatePath      = "template.yml"
	testThreatCWE         = "CWE-79"
	testThreatXSS         = "xss"
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

func TestBriefToolSignalsRequireSecurityUsageEvidence(t *testing.T) {
	taxonomy := &gitbrief.Taxonomy{Function: []string{testSecurityScanKind}}
	tools := map[string][]gitbrief.Detection{
		testSecurityCategory: {
			{Name: "applicable", Category: testSecurityCategory, Confidence: gitbrief.ConfidenceMedium, Taxonomy: taxonomy},
			{Name: "configured", Category: testSecurityCategory, Confidence: gitbrief.ConfidenceMedium, ConfigFiles: []string{"scanner.yml"}, Taxonomy: taxonomy},
			{Name: "declared", Category: testSecurityCategory, Confidence: gitbrief.ConfidenceHigh, Taxonomy: taxonomy},
		},
	}

	signals := briefToolSignals(tools)
	if containsExactSignal(signals, Signal{Check: checkSecurityTool, Kind: testSecurityScanKind, Name: "applicable"}) {
		t.Fatalf("applicability-only security tool emitted: %#v", signals)
	}
	for _, wanted := range []Signal{
		{Check: checkSecurityTool, Kind: testSecurityScanKind, Name: "configured", Path: "scanner.yml"},
		{Check: checkSecurityTool, Kind: testSecurityScanKind, Name: "declared"},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("missing configured security tool %#v: %#v", wanted, signals)
		}
	}
}

func TestRunBriefRefreshesThreatsForCheckedTools(t *testing.T) {
	tool := &kb.ToolDef{
		Tool:     kb.ToolInfo{Name: "Template Engine", Category: "framework"},
		Detect:   kb.DetectInfo{Files: []string{testTemplatePath}},
		Config:   kb.ConfigInfo{Files: []string{testTemplatePath}},
		Taxonomy: kb.Taxonomy{Function: []string{"templating"}},
	}
	source := &kb.KnowledgeBase{
		Tools:          []*kb.ToolDef{tool},
		ByName:         map[string]*kb.ToolDef{tool.Tool.Name: tool},
		ByCategory:     map[string][]*kb.ToolDef{tool.Tool.Category: {tool}},
		Ecosystems:     make(map[string][]*kb.ToolDef),
		Threats:        map[string]kb.ThreatDef{testThreatXSS: {ID: testThreatXSS, CWE: testThreatCWE}},
		ThreatMappings: []kb.ThreatMapping{{Match: []string{"function:templating"}, Threats: []string{testThreatXSS}}},
	}
	knowledge := signalKnowledgeBase(source)
	detectors := &localDetectors{
		knowledge:   knowledge,
		briefImpact: newBriefImpactReport(knowledge),
	}
	current := emptyCommitState()
	stats := &scanStats{detectors: map[string]*detectorStats{detectorBrief: {}}}

	detectors.runBrief(
		fstest.MapFS{testTemplatePath: {Data: []byte("enabled: true\n")}},
		[]string{testTemplatePath},
		true,
		false,
		&current,
		stats,
	)
	wanted := Signal{
		Check: checkThreatSurface,
		Kind:  testThreatXSS,
		Name:  "Template Engine",
		Value: testThreatCWE,
		Path:  testTemplatePath,
	}
	if !hasSignal(current.signals, wanted) {
		t.Fatalf("threat signal was not added: %#v", current.signals)
	}

	detectors.runBrief(
		fstest.MapFS{},
		[]string{testTemplatePath},
		true,
		false,
		&current,
		stats,
	)
	if hasSignal(current.signals, wanted) {
		t.Fatalf("removed threat signal remains: %#v", current.signals)
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
			name:   "dependency lockfile modified",
			change: githistory.Change{Path: "yarn.lock", OldOID: "1", NewOID: "2"},
			want:   true,
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
