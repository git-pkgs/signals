package main

import (
	"path"
	"sort"
	"strconv"
	"strings"

	actionlint "actionlint.kjanat.dev"
)

const (
	checkCacheMode       = "Cache-Mode"
	checkJobTimeout      = "Job-Timeout"
	checkPackaging       = "Packaging"
	checkRunnerSelection = "Runner-Selection"

	workflowObservationTopLevel = "topLevel"
	workflowObservationJobLevel = "jobLevel"
	packagingKindPackage        = "package"
	packagingKindPublish        = "publish"
	packagingNameNPM            = "npm"
	packagingNameContainer      = "container image"
	packagingNameGoReleaser     = "GoReleaser"
	packagingNamePyPI           = "PyPI"
	pypiPublishAction           = "pypa/gh-action-pypi-publish"
	runnerKindDynamic           = "dynamic"
	runnerKindGroup             = "group"
	runnerKindSelfHosted        = "self-hosted"
	buildName                   = "build"
	minimumPackagingFields      = 2
)

func workflowObservationSignals(filePath string, workflow *actionlint.Workflow) []Signal {
	signals := cacheModeSignals(filePath, workflow)
	signals = append(signals, jobTimeoutSignals(filePath, workflow)...)
	signals = append(signals, runnerSelectionSignals(filePath, workflow)...)
	signals = append(signals, packagingSignals(filePath, workflow)...)
	signals = append(signals, packageProvenanceSignals(filePath, workflow)...)
	return signals
}

func runnerSelectionSignals(filePath string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil || job.RunsOn == nil {
			continue
		}
		runner := job.RunsOn
		jobName := workflowJobName(job)
		if runner.Group != nil {
			signals = append(signals, Signal{
				Check: checkRunnerSelection,
				Kind:  runnerKindGroup,
				Name:  jobName,
				Value: workflowStringValue(runner.Group.Value),
				Path:  filePath,
			})
		}
		labels := runnerLabels(runner.Labels)
		if containsFold(labels, runnerKindSelfHosted) {
			signals = append(signals, Signal{
				Check: checkRunnerSelection,
				Kind:  runnerKindSelfHosted,
				Name:  jobName,
				Value: strings.Join(labels, ","),
				Path:  filePath,
			})
		}
		var expression *actionlint.String
		if runner.Expression != nil {
			expression = runner.Expression
		} else if runner.LabelsExpr != nil {
			expression = runner.LabelsExpr
		}
		if expression != nil {
			signals = append(signals, Signal{
				Check: checkRunnerSelection,
				Kind:  runnerKindDynamic,
				Name:  jobName,
				Value: workflowStringValue(expression.Value),
				Path:  filePath,
			})
		}
	}
	return signals
}

func runnerLabels(labels []*actionlint.String) []string {
	values := make([]string, 0, len(labels))
	for _, label := range labels {
		if label != nil {
			values = append(values, strings.TrimSpace(label.Value))
		}
	}
	sort.Strings(values)
	return values
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func workflowStringValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}") {
		return "expression:" + strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "${{"), "}}"))
	}
	return value
}

func cacheModeSignals(filePath string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	if workflow.CacheMode != nil {
		signals = append(signals, Signal{
			Check: checkCacheMode,
			Kind:  workflowObservationTopLevel,
			Value: workflow.CacheMode.Kind.String(),
			Path:  filePath,
			Line:  posLine(workflow.CacheMode.Pos),
		})
	}
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil || job.CacheMode == nil {
			continue
		}
		signals = append(signals, Signal{
			Check: checkCacheMode,
			Kind:  workflowObservationJobLevel,
			Name:  workflowJobName(job),
			Value: job.CacheMode.Kind.String(),
			Path:  filePath,
			Line:  posLine(job.CacheMode.Pos),
		})
	}
	return signals
}

func jobTimeoutSignals(filePath string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil || job.TimeoutMinutes == nil {
			continue
		}
		signals = append(signals, Signal{
			Check: checkJobTimeout,
			Kind:  workflowObservationJobLevel,
			Name:  workflowJobName(job),
			Value: workflowTimeoutValue(job.TimeoutMinutes),
			Path:  filePath,
			Line:  posLine(job.TimeoutMinutes.Pos),
		})
	}
	return signals
}

func workflowTimeoutValue(timeout *actionlint.Float) string {
	if timeout.Expression != nil {
		expression := strings.TrimSpace(timeout.Expression.Value)
		expression = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, "${{"), "}}"))
		return "expression:" + expression
	}
	return strconv.FormatFloat(timeout.Value, 'f', -1, 64)
}

func packagingSignals(filePath string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		walkWorkflowSteps(job.Steps, func(step *actionlint.Step) {
			switch execution := step.Exec.(type) {
			case *actionlint.ExecAction:
				if signal, ok := packagingActionSignal(filePath, execution, step.Pos); ok {
					signals = append(signals, signal)
				}
			case *actionlint.ExecRun:
				if execution != nil && execution.Run != nil {
					signals = append(signals, packagingCommandSignals(filePath, execution.Run)...)
				}
			}
		})
	}
	return signals
}

func packagingActionSignal(filePath string, execution *actionlint.ExecAction, pos *actionlint.Pos) (Signal, bool) {
	if execution == nil || execution.Uses == nil {
		return Signal{}, false
	}
	action, _, _ := strings.Cut(strings.TrimPrefix(strings.ToLower(execution.Uses.Value), "actions://"), "@")
	kind, name := packagingAction(action, execution.Inputs)
	if kind == "" {
		return Signal{}, false
	}
	return Signal{
		Check: checkPackaging,
		Kind:  kind,
		Name:  name,
		Value: action,
		Path:  filePath,
		Line:  posLine(pos),
	}, true
}

func packagingAction(action string, inputs map[string]*actionlint.Input) (string, string) {
	switch action {
	case pypiPublishAction:
		return packagingKindPublish, packagingNamePyPI
	case "rubygems/release-gem":
		return packagingKindPublish, "RubyGems"
	case "softprops/action-gh-release", "ncipollo/release-action":
		return packagingKindPublish, "GitHub Release"
	case "helm/chart-releaser-action":
		return packagingKindPublish, "Helm"
	case "docker/build-push-action":
		if inputValue(inputs, "push") == "true" {
			return packagingKindPublish, packagingNameContainer
		}
		return packagingKindPackage, packagingNameContainer
	case "goreleaser/goreleaser-action":
		if strings.Contains(strings.ToLower(inputValue(inputs, "args")), "release") {
			return packagingKindPublish, packagingNameGoReleaser
		}
		return packagingKindPackage, packagingNameGoReleaser
	default:
		return "", ""
	}
}

func inputValue(inputs map[string]*actionlint.Input, name string) string {
	input := inputs[name]
	if input == nil || input.Value == nil {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(input.Value.Value))
}

func packagingCommandSignals(filePath string, run *actionlint.String) []Signal {
	baseLine := posLine(run.Pos)
	var signals []Signal
	for index, line := range strings.Split(run.Value, "\n") {
		for _, segment := range commandSegments(line) {
			kind, name := packagingCommand(strings.Fields(segment))
			if kind == "" {
				continue
			}
			signals = append(signals, Signal{
				Check: checkPackaging,
				Kind:  kind,
				Name:  name,
				Path:  filePath,
				Line:  baseLine + uint(index),
			})
		}
	}
	return signals
}

func commandSegments(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		return r == ';' || r == '&' || r == '|'
	})
}

func packagingCommand(fields []string) (string, string) {
	fields = unwrapCommand(fields)
	if len(fields) < minimumPackagingFields {
		return "", ""
	}
	command := path.Base(fields[0])
	args := fields[1:]
	switch command {
	case packagingNameNPM, "pnpm":
		return packagingVerb(command, args[0], "pack", "publish")
	case "yarn":
		if len(args) > 1 && args[0] == packagingNameNPM {
			return packagingVerb(command, args[1], "pack", "publish")
		}
		return packagingVerb(command, args[0], "pack", "publish")
	case "cargo":
		return packagingVerb("cargo", args[0], "package", "publish")
	case "gem":
		return packagingVerb("RubyGems", args[0], buildName, "push")
	case "python", "python3", "py":
		return pythonPackagingCommand(args)
	case "twine":
		if args[0] == "upload" {
			return packagingKindPublish, packagingNamePyPI
		}
	case "dotnet":
		return dotnetPackagingCommand(args)
	case dockerName, "podman":
		return containerPackagingCommand(args)
	case "mvn", "mvnw":
		return packagingVerb("Maven", args[0], "package", "deploy")
	case "gradle", "gradlew":
		return packagingVerb("Gradle", args[0], "assemble", "publish")
	case "gh":
		return githubReleaseCommand(args)
	case "goreleaser":
		return packagingVerb(packagingNameGoReleaser, args[0], buildName, "release")
	case "helm":
		return packagingVerb("Helm", args[0], "package", "push")
	}
	return "", ""
}

func dotnetPackagingCommand(args []string) (string, string) {
	if args[0] == "pack" {
		return packagingKindPackage, "NuGet"
	}
	if len(args) > 1 && args[0] == "nuget" && args[1] == "push" {
		return packagingKindPublish, "NuGet"
	}
	return "", ""
}

func containerPackagingCommand(args []string) (string, string) {
	if args[0] == buildName ||
		(len(args) > 1 && args[0] == "buildx" && args[1] == buildName) {
		return packagingKindPackage, packagingNameContainer
	}
	if args[0] == "push" {
		return packagingKindPublish, packagingNameContainer
	}
	return "", ""
}

func githubReleaseCommand(args []string) (string, string) {
	if len(args) > 1 && args[0] == "release" && args[1] == "create" {
		return packagingKindPublish, "GitHub Release"
	}
	return "", ""
}

func unwrapCommand(fields []string) []string {
	for len(fields) > 0 {
		if strings.Contains(fields[0], "=") && !strings.HasPrefix(fields[0], "=") {
			fields = fields[1:]
			continue
		}
		if fields[0] == "sudo" || fields[0] == "env" {
			fields = fields[1:]
			continue
		}
		break
	}
	return fields
}

func packagingVerb(name, verb, packageVerb, publishVerb string) (string, string) {
	switch verb {
	case packageVerb:
		return packagingKindPackage, name
	case publishVerb:
		return packagingKindPublish, name
	default:
		return "", ""
	}
}

func pythonPackagingCommand(args []string) (string, string) {
	if len(args) < 2 || args[0] != "-m" {
		return "", ""
	}
	if args[1] == buildName {
		return packagingKindPackage, "Python"
	}
	if len(args) > 2 && args[1] == "twine" && args[2] == "upload" {
		return packagingKindPublish, packagingNamePyPI
	}
	return "", ""
}
