package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/raw"
	"github.com/ossf/scorecard/v5/clients"
)

const (
	checkBinaryArtifacts      = "Binary-Artifacts"
	checkDangerousWorkflow    = "Dangerous-Workflow"
	checkDependencyUpdateTool = "Dependency-Update-Tool"
	checkFuzzing              = "Fuzzing"
	checkLicense              = "License"
	checkPinnedDependencies   = "Pinned-Dependencies"
	checkSAST                 = "SAST"
	checkSBOM                 = "SBOM"
	checkSecurityPolicy       = "Security-Policy"
	checkTokenPermissions     = "Token-Permissions"
)

type Signal struct {
	Check string
	Kind  string
	Name  string
	Value string
	Path  string
	Line  uint
}

type detectionImpact uint8

const (
	impactNone detectionImpact = iota
	impactPartial
	impactFull
)

type detector struct {
	name   string
	impact func(string) detectionImpact
	run    func(*checker.CheckRequest) ([]Signal, error)
}

type detectionScope struct {
	impact detectionImpact
	paths  map[string]bool
}

var scorecardDetectors = []detector{
	{name: checkBinaryArtifacts, impact: impactAnyPartial, run: detectBinaryArtifacts},
	{name: checkDangerousWorkflow, impact: impactWorkflow, run: detectDangerousWorkflows},
	{name: checkDependencyUpdateTool, impact: impactDependencyUpdate, run: detectDependencyUpdateTools},
	{name: checkFuzzing, impact: impactFuzzing, run: detectFuzzing},
	{name: checkLicense, impact: impactLicense, run: detectLicenses},
	{name: checkPinnedDependencies, impact: impactPinnedDependencies, run: detectPinnedDependencies},
	{name: checkSAST, impact: impactSAST, run: detectSAST},
	{name: checkSBOM, impact: impactSBOM, run: detectSBOMs},
	{name: checkSecurityPolicy, impact: impactSecurityPolicy, run: detectSecurityPolicies},
	{name: checkTokenPermissions, impact: impactWorkflow, run: detectTokenPermissions},
}

func (d detector) scope(paths []string, forceFull bool) detectionScope {
	if forceFull {
		return detectionScope{impact: impactFull}
	}
	scope := detectionScope{paths: make(map[string]bool)}
	for _, path := range paths {
		impact := d.impact(path)
		if impact == impactFull {
			return detectionScope{impact: impactFull}
		}
		if impact == impactPartial {
			scope.impact = impactPartial
			scope.paths[path] = true
		}
	}
	return scope
}

func (d detector) detect(ctx context.Context, client clients.RepoClient) ([]Signal, error) {
	request := &checker.CheckRequest{
		Ctx:        ctx,
		RepoClient: client,
	}
	signals, err := d.run(request)
	if err != nil {
		return nil, err
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func detectBinaryArtifacts(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.BinaryArtifacts(request)
	if err != nil {
		return nil, err
	}
	signals := make([]Signal, 0, len(data.Files))
	for _, file := range data.Files {
		signals = append(signals, signalFromFile(checkBinaryArtifacts, "artifact", "", "", file))
	}
	return signals, nil
}

func detectDangerousWorkflows(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.DangerousWorkflow(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, workflow := range data.Workflows {
		signals = append(signals, signalFromFile(
			checkDangerousWorkflow,
			string(workflow.Type),
			workflowJobName(workflow.Job),
			workflow.File.Snippet,
			workflow.File,
		))
	}
	return signals, nil
}

func detectDependencyUpdateTools(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.DependencyUpdateTool(request.RepoClient)
	if err != nil {
		return nil, err
	}
	return toolSignals(checkDependencyUpdateTool, "tool", data.Tools), nil
}

func detectFuzzing(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.Fuzzing(request)
	if err != nil {
		return nil, err
	}
	return toolSignals(checkFuzzing, "fuzzer", data.Fuzzers), nil
}

func detectLicenses(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.License(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, license := range data.LicenseFiles {
		signals = append(signals, signalFromFile(
			checkLicense,
			"license",
			license.LicenseInformation.SpdxID,
			license.LicenseInformation.Name,
			license.File,
		))
	}
	return signals, nil
}

func detectPinnedDependencies(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.PinningDependencies(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, dependency := range data.Dependencies {
		if dependency.Location == nil {
			continue
		}
		signal := Signal{
			Check: checkPinnedDependencies,
			Kind:  string(dependency.Type),
			Name:  stringValue(dependency.Name),
			Value: pinValue(dependency),
			Path:  dependency.Location.Path,
			Line:  dependency.Location.Offset,
		}
		signals = append(signals, signal)
	}
	return signals, nil
}

func detectSAST(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.SAST(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, workflow := range data.Workflows {
		signals = append(signals, signalFromFile(checkSAST, "tool", string(workflow.Type), "", workflow.File))
	}
	return signals, nil
}

func detectSBOMs(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.SBOM(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, sbom := range data.SBOMFiles {
		signals = append(signals, signalFromFile(checkSBOM, "document", sbom.Name, "", sbom.File))
	}
	return signals, nil
}

func detectSecurityPolicies(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.SecurityPolicy(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, policy := range data.PolicyFiles {
		signals = append(signals, signalFromFile(checkSecurityPolicy, "policy", "", "", policy.File))
		for _, info := range policy.Information {
			signals = append(signals, Signal{
				Check: checkSecurityPolicy,
				Kind:  string(info.InformationType),
				Value: info.InformationValue.Match,
				Path:  policy.File.Path,
				Line:  info.InformationValue.LineNumber,
			})
		}
	}
	return signals, nil
}

func detectTokenPermissions(request *checker.CheckRequest) ([]Signal, error) {
	data, err := raw.TokenPermissions(request)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, permission := range data.TokenPermissions {
		signal := Signal{
			Check: checkTokenPermissions,
			Kind:  stringValue(permission.LocationType),
			Name:  stringValue(permission.Name),
			Value: permissionValue(permission),
		}
		if signal.Kind == "" {
			signal.Kind = "permission"
		}
		if permission.File != nil {
			signal.Path = permission.File.Path
			signal.Line = permission.File.Offset
		}
		if job := workflowJobName(permission.Job); job != "" {
			if signal.Name == "" {
				signal.Name = job
			} else {
				signal.Name = fmt.Sprintf("%s (%s)", signal.Name, job)
			}
		}
		signals = append(signals, signal)
	}
	return signals, nil
}

func impactAnyPartial(string) detectionImpact {
	return impactPartial
}

func impactWorkflow(path string) detectionImpact {
	if strings.HasPrefix(strings.ToLower(path), ".github/workflows/") {
		return impactPartial
	}
	return impactNone
}

func impactDependencyUpdate(path string) detectionImpact {
	switch strings.ToLower(path) {
	case ".github/dependabot.yml", ".github/dependabot.yaml",
		"renovate.json", "renovate.json5", ".github/renovate.json", ".github/renovate.json5",
		".gitlab/renovate.json", ".gitlab/renovate.json5", ".renovaterc", ".renovaterc.json",
		".renovaterc.json5", ".scala-steward.conf", "scala-steward.conf",
		".github/.scala-steward.conf", ".github/scala-steward.conf",
		".config/.scala-steward.conf", ".config/scala-steward.conf":
		return impactFull
	default:
		return impactNone
	}
}

func impactFuzzing(path string) detectionImpact {
	if path == ".clusterfuzzlite/Dockerfile" {
		return impactFull
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".erl", ".hrl", ".hs", ".lhs", ".ex", ".exs", ".gleam", ".js", ".jsx",
		".ts", ".tsx", ".py", ".c", ".cc", ".cpp", ".rs", ".java", ".swift", ".cs", ".fs":
		return impactPartial
	default:
		return impactNone
	}
}

func impactLicense(path string) detectionImpact {
	if !strings.Contains(path, "/") && raw.TestLicense(path) {
		return impactFull
	}
	return impactNone
}

func impactPinnedDependencies(path string) detectionImpact {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(name, ".csproj") ||
		(strings.HasPrefix(name, "directory.") && strings.HasSuffix(name, ".props")) {
		return impactFull
	}
	return impactPartial
}

func impactSAST(path string) detectionImpact {
	if impactWorkflow(path) == impactPartial || strings.EqualFold(filepath.Base(path), "pom.xml") {
		return impactPartial
	}
	return impactNone
}

func impactSBOM(path string) detectionImpact {
	if strings.Contains(path, "/") {
		return impactNone
	}
	lower := strings.ToLower(path)
	for _, suffix := range []string{
		".cdx.json", ".cdx.xml", ".spdx", ".spdx.json", ".spdx.xml",
		".spdx.yml", ".spdx.yaml", ".spdx.rdf", ".spdx.rdf.xml",
	} {
		if strings.HasSuffix(lower, suffix) {
			return impactFull
		}
	}
	return impactNone
}

func impactSecurityPolicy(path string) detectionImpact {
	switch strings.ToLower(path) {
	case "security.md", ".github/security.md", "docs/security.md",
		"security.markdown", ".github/security.markdown", "docs/security.markdown",
		"security.adoc", ".github/security.adoc", "docs/security.adoc",
		"security.rst", ".github/security.rst", "doc/security.rst", "docs/security.rst":
		return impactFull
	default:
		return impactNone
	}
}

func signalFromFile(check, kind, name, value string, file checker.File) Signal {
	return Signal{
		Check: check,
		Kind:  kind,
		Name:  name,
		Value: value,
		Path:  file.Path,
		Line:  file.Offset,
	}
}

func toolSignals(check, kind string, tools []checker.Tool) []Signal {
	var signals []Signal
	for _, tool := range tools {
		if len(tool.Files) == 0 {
			signals = append(signals, Signal{Check: check, Kind: kind, Name: tool.Name})
			continue
		}
		for _, file := range tool.Files {
			signals = append(signals, signalFromFile(check, kind, tool.Name, file.Snippet, file))
		}
	}
	return signals
}

func workflowJobName(job *checker.WorkflowJob) string {
	if job == nil {
		return ""
	}
	if job.Name != nil && *job.Name != "" {
		return *job.Name
	}
	return stringValue(job.ID)
}

func pinValue(dependency checker.Dependency) string {
	switch {
	case dependency.Pinned == nil:
		return "unknown"
	case *dependency.Pinned && dependency.PinnedAt != nil:
		return "pinned@" + *dependency.PinnedAt
	case *dependency.Pinned:
		return "pinned"
	default:
		return "unpinned"
	}
}

func permissionValue(permission checker.TokenPermission) string {
	value := string(permission.Type)
	if permission.Value != nil && *permission.Value != "" && *permission.Value != value {
		if value == "" {
			return *permission.Value
		}
		return value + ":" + *permission.Value
	}
	return value
}

func stringValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
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
