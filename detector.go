package main

import (
	"fmt"
	"sort"
)

const (
	checkBinaryArtifacts      = "Binary-Artifacts"
	checkDangerousWorkflow    = "Dangerous-Workflow"
	checkDependencyUpdateTool = "Dependency-Update-Tool"
	checkFuzzing              = "Fuzzing"
	checkLicense              = "License"
	checkSAST                 = "SAST"
	checkSBOM                 = "SBOM"
	checkSecurityPolicy       = "Security-Policy"
	checkTokenPermissions     = "Token-Permissions"
	signalKindDeclaration     = "declaration"
	signalKindFileReference   = "file-reference"
	signalKindLicense         = "license"
	signalKindNotice          = "notice"
	signalKindTool            = "tool"
	sastToolSonar             = "Sonar"
)

type Signal struct {
	Check string
	Kind  string
	Name  string
	Value string
	Path  string
	Line  uint
}

func sortSignals(signals []Signal) {
	sort.Slice(signals, func(i, j int) bool {
		return signalKey(signals[i]) < signalKey(signals[j])
	})
}

func deduplicateSignals(signals []Signal) []Signal {
	if len(signals) < 2 {
		return signals
	}
	result := signals[:1]
	for _, signal := range signals[1:] {
		if signal != result[len(result)-1] {
			result = append(result, signal)
		}
	}
	return result
}

func signalKey(signal Signal) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%010d",
		signal.Check, signal.Kind, signal.Name, signal.Value, signal.Path, signal.Line)
}
