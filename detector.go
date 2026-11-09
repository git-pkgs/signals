package main

import (
	"fmt"
	"sort"
)

const (
	checkAgentSkill            = "Agent-Skill"
	checkAttestation           = "Attestation"
	checkArtifactProvenance    = "Artifact-Provenance"
	checkArtifactSigning       = "Artifact-Signing"
	checkBinaryArtifacts       = "Binary-Artifacts"
	checkCertificate           = "Certificate"
	checkDangerousWorkflow     = "Dangerous-Workflow"
	checkDependencyUpdateTool  = "Dependency-Update-Tool"
	checkFuzzing               = "Fuzzing"
	checkLicense               = "License"
	checkRepositoryOwnership   = "Repository-Ownership"
	checkSARIF                 = "SARIF"
	checkSAST                  = "SAST"
	checkSBOM                  = "SBOM"
	checkSBOMGeneration        = "SBOM-Generation"
	checkSecurityChangelog     = "Security-Changelog"
	checkSecurityDocumentation = "Security-Documentation"
	checkSecurityPolicy        = "Security-Policy"
	checkSensitiveIgnore       = "Sensitive-Ignore"
	checkSubresourceIntegrity  = "Subresource-Integrity"
	checkTokenPermissions      = "Token-Permissions"
	signalKindCandidate        = "candidate"
	signalKindDeclaration      = "declaration"
	signalKindChangelogEntry   = "entry"
	signalKindAdvisory         = "advisory"
	signalKindFileReference    = "file-reference"
	signalKindLicense          = "license"
	signalKindNotice           = "notice"
	signalKindTool             = "tool"
	sastToolSonar              = "Sonar"
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
