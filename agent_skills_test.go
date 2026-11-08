package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	githistory "github.com/git-pkgs/history"
)

const testAgentSkillName = "audit"

func TestAgentSkillSignalsDescribeInstructionsToolsAndScripts(t *testing.T) {
	const skillPath = ".claude/skills/audit/SKILL.md"
	const scriptPath = ".claude/skills/audit/scripts/run.sh"
	script := []byte("#!/bin/sh\necho audit\n")
	instructions := []byte("Check the repository.")
	fsys := fstest.MapFS{
		skillPath: {
			Data: []byte("---\nname: audit\ndescription: Audit the repository\nallowed-tools: Read Grep\n---\nCheck the repository.\n"),
		},
		scriptPath: {Data: script, Mode: 0o755},
	}

	signals, err := agentSkillSignals(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []Signal{
		{Check: checkAgentSkill, Kind: agentSkillKind, Name: testAgentSkillName, Value: "files=1; scripts=1; warnings=0", Path: skillPath},
		{Check: checkAgentSkill, Kind: "allowed-tools", Name: testAgentSkillName, Value: "Read Grep", Path: skillPath},
		{
			Check: checkAgentSkill,
			Kind:  "instructions",
			Name:  testAgentSkillName,
			Value: fmt.Sprintf("sha256:%x", sha256.Sum256(instructions)),
			Path:  skillPath,
		},
		{
			Check: checkAgentSkill,
			Kind:  "script",
			Name:  testAgentSkillName,
			Value: fmt.Sprintf("sha256:%x; mode=0755", sha256.Sum256(script)),
			Path:  scriptPath,
		},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signals missing %#v:\n%#v", wanted, signals)
		}
	}
}

func TestAgentSkillSignalsSkipNonProjectRoles(t *testing.T) {
	fsys := fstest.MapFS{
		"testdata/example/SKILL.md": {
			Data: []byte("---\nname: example\ndescription: Example skill\n---\nExample.\n"),
		},
		".agents/skills/project/SKILL.md": {
			Data: []byte("---\nname: project\ndescription: Project skill\n---\nProject.\n"),
		},
	}

	signals, err := agentSkillSignals(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for _, signal := range signals {
		if strings.HasPrefix(signal.Path, "testdata/") {
			t.Fatalf("fixture skill reported: %#v", signal)
		}
	}
	if !containsExactSignal(signals, Signal{
		Check: checkAgentSkill,
		Kind:  agentSkillKind,
		Name:  "project",
		Value: "files=0; scripts=0; warnings=0",
		Path:  ".agents/skills/project/SKILL.md",
	}) {
		t.Fatalf("project skill missing: %#v", signals)
	}
}

func TestAgentSkillsAffectedBySkillPackageChanges(t *testing.T) {
	signals := signalMap(Signal{
		Check: checkAgentSkill,
		Kind:  agentSkillKind,
		Name:  testAgentSkillName,
		Path:  ".claude/skills/audit/SKILL.md",
	})
	tests := []struct {
		name    string
		changes []githistory.Change
		want    bool
	}{
		{name: "new skill", changes: []githistory.Change{{Path: ".agents/skills/new/SKILL.md"}}, want: true},
		{name: "existing script", changes: []githistory.Change{{Path: ".claude/skills/audit/scripts/run.sh"}}, want: true},
		{name: "unrelated file", changes: []githistory.Change{{Path: "main.go"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := agentSkillsAffected(test.changes, signals); got != test.want {
				t.Errorf("agentSkillsAffected = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLogTracksAgentSkillChanges(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	const skillPath = ".claude/skills/audit/SKILL.md"
	const scriptPath = ".claude/skills/audit/scripts/run.sh"
	writeFile(t, repo, skillPath, "---\nname: audit\ndescription: Audit the repository\nallowed-tools: Read\n---\nCheck the repository.\n")
	writeFile(t, repo, scriptPath, "#!/bin/sh\necho first\n")
	gitRun(t, repo, "add", "-f", ".claude")
	gitRun(t, repo, "commit", "-m", "Add agent skill")

	writeFile(t, repo, skillPath, "---\nname: audit\ndescription: Audit the repository\nallowed-tools: Read Bash\n---\nCheck the repository.\n")
	writeFile(t, repo, scriptPath, "#!/bin/sh\necho second\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Expand agent skill")

	if err := os.RemoveAll(filepath.Join(repo, ".claude", "skills", "audit")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-m", "Remove agent skill")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	output := stdout.String()
	for signal, counts := range map[string][2]int{
		"Agent-Skill/skill audit":         {1, 1},
		"Agent-Skill/allowed-tools audit": {2, 2},
		"Agent-Skill/instructions audit":  {1, 1},
		"Agent-Skill/script audit":        {2, 2},
	} {
		additions, removals := counts[0], counts[1]
		if got := strings.Count(output, "+ "+signal); got != additions {
			t.Errorf("%s additions = %d, want %d:\n%s", signal, got, additions, output)
		}
		if got := strings.Count(output, "- "+signal); got != removals {
			t.Errorf("%s removals = %d, want %d:\n%s", signal, got, removals, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}
