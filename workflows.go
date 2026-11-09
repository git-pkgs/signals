package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"

	actionlint "actionlint.kjanat.dev"
	githistory "github.com/git-pkgs/history"
)

const (
	workflowKindScriptInjection   = "scriptInjection"
	workflowKindUntrustedCheckout = "untrustedCheckout"
	permissionKindTopLevel        = "topLevel"
	permissionKindJobLevel        = "jobLevel"
	permissionKindReusableCall    = "reusableCall"
	permissionKindReusableJob     = "reusableJob"
	permissionKindReusableTop     = "reusableTopLevel"
	workflowExpressionOpening     = "${{"
	workflowExpressionClosing     = "}}"
)

var dangerousToJSONPattern = regexp.MustCompile(`(?i)tojson\s*\(\s*github(?:\.event)?\s*\)`)

type workflowCacheKey struct {
	oid  string
	path string
}

func workflowsAffected(changes []githistory.Change) bool {
	for _, change := range changes {
		if isWorkflowPath(change.Path) {
			return true
		}
	}
	return false
}

func isWorkflowPath(path string) bool {
	relative, found := strings.CutPrefix(path, ".github/workflows/")
	if !found || strings.Contains(relative, "/") {
		return false
	}
	ext := strings.ToLower(fsPathExt(path))
	return ext == ".yml" || ext == ".yaml"
}

func fsPathExt(path string) string {
	if dot := strings.LastIndexByte(path, '.'); dot >= 0 {
		return path[dot:]
	}
	return ""
}

func workflowSignalsForChanges(
	tree fs.FS,
	changes []githistory.Change,
	cache map[workflowCacheKey][]Signal,
	shell *shellAnalyzer,
) ([]Signal, []string, error) {
	var signals []Signal
	var paths []string
	for _, change := range changes {
		path := change.Path
		if !isWorkflowPath(path) {
			continue
		}
		paths = append(paths, path)

		key := workflowCacheKey{oid: nonzeroOID(change.NewOID), path: path}
		if key.oid != "" {
			if cached, ok := cache[key]; ok {
				signals = append(signals, cached...)
				continue
			}
		}

		data, err := fs.ReadFile(tree, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read workflow %s: %w", path, err)
		}
		parsed, err := workflowFileSignals(path, data, shell)
		if err != nil {
			return nil, nil, err
		}
		signals = append(signals, parsed...)
		if key.oid != "" {
			cache[key] = parsed
		}
	}
	sortSignals(signals)
	return deduplicateSignals(signals), paths, nil
}

func allWorkflowSignals(tree fs.FS, shell *shellAnalyzer) ([]Signal, error) {
	var signals []Signal
	err := fs.WalkDir(tree, ".github/workflows", func(path string, entry fs.DirEntry, walkErr error) error {
		if errors.Is(walkErr, fs.ErrNotExist) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !isWorkflowPath(path) {
			return nil
		}
		data, err := fs.ReadFile(tree, path)
		if err != nil {
			return fmt.Errorf("read workflow %s: %w", path, err)
		}
		parsed, err := workflowFileSignals(path, data, shell)
		if err != nil {
			return err
		}
		signals = append(signals, parsed...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func workflowFileSignals(path string, data []byte, analyzers ...*shellAnalyzer) ([]Signal, error) {
	workflow, parseErrors := actionlint.Parse(data)
	if workflow == nil {
		if len(parseErrors) == 0 {
			return nil, fmt.Errorf("parse workflow %s", path)
		}
		return nil, fmt.Errorf("parse workflow %s: %w", path, parseErrors[0])
	}
	signals := dangerousWorkflowSignals(path, workflow)
	signals = append(signals, tokenPermissionSignals(path, workflow)...)
	signals = append(signals, sastWorkflowSignals(path, workflow)...)
	signals = append(signals, workflowObservationSignals(path, data, workflow)...)
	signals = append(signals, artifactProvenanceSignals(path, workflow)...)
	var shell *shellAnalyzer
	if len(analyzers) > 0 {
		shell = analyzers[0]
	}
	signals = append(signals, shellWorkflowSignals(path, data, workflow, shell)...)
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func artifactProvenanceSignals(path string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil {
			kind, name := artifactProvenanceAction(job.WorkflowCall.Uses.Value)
			if kind != "" {
				signals = append(signals, Signal{
					Check: checkArtifactProvenance,
					Kind:  kind,
					Name:  name,
					Path:  path,
				})
			}
		}
		walkWorkflowSteps(job.Steps, func(step *actionlint.Step) {
			execution, ok := step.Exec.(*actionlint.ExecAction)
			if !ok || execution == nil || execution.Uses == nil {
				return
			}
			kind, name := artifactProvenanceAction(execution.Uses.Value)
			if kind == "" {
				return
			}
			signals = append(signals, Signal{
				Check: checkArtifactProvenance,
				Kind:  kind,
				Name:  name,
				Path:  path,
			})
		})
	}
	return signals
}

func artifactProvenanceAction(uses string) (kind, name string) {
	action := workflowActionReference(uses)
	switch {
	case action == "actions/attest" || strings.HasPrefix(action, "actions/attest-"):
		return "attestation-action", action
	case strings.HasPrefix(action, "slsa-framework/slsa-github-generator/"):
		return "slsa-generator", action
	default:
		return "", ""
	}
}

func shellWorkflowSignals(
	path string,
	data []byte,
	workflow *actionlint.Workflow,
	shell *shellAnalyzer,
) []Signal {
	if shell == nil {
		return nil
	}
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		walkWorkflowSteps(job.Steps, func(step *actionlint.Step) {
			execution, ok := step.Exec.(*actionlint.ExecRun)
			if !ok || execution == nil || execution.Run == nil ||
				!workflowRunUsesShell(execution.Shell, job, workflow) {
				return
			}
			line := workflowRunLineOffset(data, execution)
			script := sanitizeWorkflowExpressions(execution.Run.Value)
			signals = append(signals, shell.scriptSignals(path, []byte(script), line)...)
		})
	}
	return signals
}

func sanitizeWorkflowExpressions(script string) string {
	data := []byte(script)
	for search := 0; search < len(data); {
		relative := bytes.Index(data[search:], []byte(workflowExpressionOpening))
		if relative < 0 {
			break
		}
		start := search + relative
		end := workflowExpressionEnd(data, start+len(workflowExpressionOpening))
		if end < 0 {
			break
		}
		for index := start; index < end; index++ {
			if data[index] != '\n' && data[index] != '\r' {
				data[index] = '_'
			}
		}
		search = end
	}
	return string(data)
}

func workflowExpressionEnd(data []byte, start int) int {
	var quote byte
	escaped := false
	for index := start; index < len(data); index++ {
		current := data[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			continue
		}
		if current == '}' && index+1 < len(data) && data[index+1] == '}' {
			return index + len(workflowExpressionClosing)
		}
	}
	return -1
}

func workflowRunLineOffset(data []byte, execution *actionlint.ExecRun) uint {
	line := posLine(execution.RunPos)
	if line == 0 {
		line = posLine(execution.Run.Pos)
	}
	if line > 0 && !workflowBlockScalar(data, line) {
		line--
	}
	return line
}

func workflowBlockScalar(data []byte, line uint) bool {
	lines := bytes.Split(data, []byte{'\n'})
	if line == 0 || int(line) > len(lines) {
		return false
	}
	text := strings.TrimSpace(string(lines[line-1]))
	_, value, ok := strings.Cut(text, ":")
	if !ok {
		return false
	}
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">")
}

func workflowRunUsesShell(shell *actionlint.String, job *actionlint.Job, workflow *actionlint.Workflow) bool {
	if shell == nil || strings.TrimSpace(shell.Value) == "" {
		shell = workflowDefaultShell(job, workflow)
	}
	if shell == nil || strings.TrimSpace(shell.Value) == "" {
		return !workflowJobUsesWindows(job)
	}
	name := strings.ToLower(strings.Fields(shell.Value)[0])
	name = fsPathBase(name)
	return shellLanguageName[name]
}

func workflowDefaultShell(job *actionlint.Job, workflow *actionlint.Workflow) *actionlint.String {
	if job != nil && job.Defaults != nil && job.Defaults.Run != nil && job.Defaults.Run.Shell != nil {
		return job.Defaults.Run.Shell
	}
	if workflow != nil && workflow.Defaults != nil && workflow.Defaults.Run != nil {
		return workflow.Defaults.Run.Shell
	}
	return nil
}

func workflowJobUsesWindows(job *actionlint.Job) bool {
	if job == nil || job.RunsOn == nil {
		return false
	}
	for _, label := range job.RunsOn.Labels {
		if label != nil && strings.Contains(strings.ToLower(label.Value), "windows") {
			return true
		}
	}
	return false
}

func fsPathBase(value string) string {
	if slash := strings.LastIndexAny(value, "/\\"); slash >= 0 {
		return value[slash+1:]
	}
	return value
}

func dangerousWorkflowSignals(path string, workflow *actionlint.Workflow) []Signal {
	triggersUntrustedCheckout := workflowHasEvent(workflow, "pull_request_target") ||
		workflowHasEvent(workflow, "workflow_run")
	jobIDs := sortedWorkflowJobIDs(workflow)
	var signals []Signal
	for _, id := range jobIDs {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		walkWorkflowSteps(job.Steps, func(step *actionlint.Step) {
			switch execution := step.Exec.(type) {
			case *actionlint.ExecAction:
				if triggersUntrustedCheckout && untrustedCheckout(execution) {
					ref := execution.Inputs["ref"].Value
					signals = append(signals, Signal{
						Check: checkDangerousWorkflow,
						Kind:  workflowKindUntrustedCheckout,
						Name:  workflowJobName(job),
						Value: ref.Value,
						Path:  path,
						Line:  posLine(step.Pos),
					})
				}
			case *actionlint.ExecRun:
				if execution != nil && execution.Run != nil {
					for _, expression := range untrustedScriptExpressions(execution.Run.Value) {
						signals = append(signals, Signal{
							Check: checkDangerousWorkflow,
							Kind:  workflowKindScriptInjection,
							Name:  workflowJobName(job),
							Value: expression,
							Path:  path,
							Line:  posLine(execution.Run.Pos),
						})
					}
				}
			}
		})
	}
	return signals
}

func workflowHasEvent(workflow *actionlint.Workflow, name string) bool {
	for _, event := range workflow.On {
		if event != nil && event.EventName() == name {
			return true
		}
	}
	return false
}

func workflowActionReference(uses string) string {
	action := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(uses)), "actions://")
	action, _, _ = strings.Cut(action, "@")
	return action
}

func untrustedCheckout(execution *actionlint.ExecAction) bool {
	if execution == nil || execution.Uses == nil {
		return false
	}
	action := workflowActionReference(execution.Uses.Value)
	if action != "actions/checkout" {
		return false
	}
	input := execution.Inputs["ref"]
	if input == nil || input.Value == nil {
		return false
	}
	ref := strings.ToLower(input.Value.Value)
	if strings.Contains(ref, "github.event.pull_request") ||
		strings.Contains(ref, "github.event.workflow_run") ||
		(strings.Contains(ref, "refs/pull/") && strings.Contains(ref, "github.event.number")) {
		return true
	}
	repository := execution.Inputs["repository"]
	if repository == nil || repository.Value == nil {
		return false
	}
	repositoryValue := strings.ToLower(repository.Value.Value)
	return strings.Contains(ref, "github.head_ref") &&
		strings.Contains(repositoryValue, "github.event.pull_request.head.repo")
}

func walkWorkflowSteps(steps []*actionlint.Step, visit func(*actionlint.Step)) {
	for _, step := range steps {
		if step == nil {
			continue
		}
		visit(step)
		if parallel, ok := step.Exec.(*actionlint.ExecParallel); ok && parallel != nil {
			walkWorkflowSteps(parallel.Steps, visit)
		}
	}
}

func untrustedScriptExpressions(script string) []string {
	var found []string
	for {
		start := strings.Index(script, "${{")
		if start < 0 {
			break
		}
		script = script[start+3:]
		end := strings.Index(script, "}}")
		if end < 0 {
			break
		}
		expression := strings.TrimSpace(script[:end])
		if expressionIsUntrusted(expression) {
			found = append(found, expression)
		}
		script = script[end+2:]
	}
	return found
}

func expressionIsUntrusted(expression string) bool {
	if dangerousToJSONPattern.MatchString(expression) {
		return true
	}
	node, err := actionlint.NewExprParser().Parse(actionlint.NewExprLexer(expression + "}}"))
	if err != nil {
		return false
	}
	checker := actionlint.NewUntrustedInputChecker(actionlint.BuiltinUntrustedInputs)
	actionlint.VisitExprNode(node, func(node, _ actionlint.ExprNode, entering bool) {
		if entering {
			checker.OnVisitNodeEnter(node)
		} else {
			checker.OnVisitNodeLeave(node)
		}
	})
	checker.OnVisitEnd()
	return len(checker.Errs()) > 0
}

func tokenPermissionSignals(path string, workflow *actionlint.Workflow) []Signal {
	topKind := permissionKindTopLevel
	var fallback *actionlint.Pos
	definition, reusable := workflow.FindWorkflowCallEvent()
	if reusable {
		topKind = permissionKindReusableTop
		fallback = definition.Pos
	}
	signals := permissionSignals(path, topKind, "", workflow.Permissions, fallback)
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		kind := permissionKindJobLevel
		if job.WorkflowCall != nil {
			kind = permissionKindReusableCall
		} else if reusable {
			kind = permissionKindReusableJob
		}
		signals = append(signals, permissionSignals(
			path,
			kind,
			workflowJobName(job),
			job.Permissions,
			job.Pos,
		)...)
	}
	return signals
}

func sastWorkflowSignals(path string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		walkWorkflowSteps(job.Steps, func(step *actionlint.Step) {
			execution, ok := step.Exec.(*actionlint.ExecAction)
			if !ok || execution == nil || execution.Uses == nil {
				return
			}
			tool := sastToolForAction(execution.Uses.Value)
			if tool == "" {
				return
			}
			signals = append(signals, Signal{
				Check: checkSAST,
				Kind:  signalKindTool,
				Name:  tool,
				Path:  path,
				Line:  posLine(step.Pos),
			})
		})
	}
	return signals
}

func sastToolForAction(uses string) string {
	action := workflowActionReference(uses)
	switch {
	case action == "github/codeql-action/analyze":
		return "CodeQL"
	case strings.HasPrefix(action, "snyk/actions/"):
		return "Snyk"
	case action == "facebook/pysa-action":
		return "Pysa"
	case action == "jetbrains/qodana-action":
		return "Qodana"
	case action == "hadolint/hadolint-action":
		return "Hadolint"
	case action == "sonarsource/sonarcloud-github-action" ||
		action == "sonarsource/sonarqube-scan-action":
		return sastToolSonar
	case action == "semgrep/semgrep-action" || action == "returntocorp/semgrep-action":
		return "Semgrep"
	case action == "checkmarx/ast-github-action":
		return "Checkmarx"
	default:
		return ""
	}
}

func permissionSignals(
	path, kind, jobName string,
	permissions *actionlint.Permissions,
	fallback *actionlint.Pos,
) []Signal {
	if permissions == nil {
		return []Signal{{
			Check: checkTokenPermissions,
			Kind:  kind,
			Name:  jobName,
			Value: "undeclared",
			Path:  path,
			Line:  posLine(fallback),
		}}
	}
	if permissions.All != nil && permissions.All.Value != "" {
		return []Signal{{
			Check: checkTokenPermissions,
			Kind:  kind,
			Name:  jobName,
			Value: permissions.All.Value,
			Path:  path,
			Line:  posLine(permissions.All.Pos),
		}}
	}
	if len(permissions.Scopes) == 0 {
		return []Signal{{
			Check: checkTokenPermissions,
			Kind:  kind,
			Name:  jobName,
			Value: "none",
			Path:  path,
			Line:  posLine(permissions.Pos),
		}}
	}

	names := make([]string, 0, len(permissions.Scopes))
	for name := range permissions.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	signals := make([]Signal, 0, len(names))
	for _, name := range names {
		scope := permissions.Scopes[name]
		if scope == nil || scope.Value == nil {
			continue
		}
		signalName := name
		if jobName != "" {
			signalName += " (" + jobName + ")"
		}
		signals = append(signals, Signal{
			Check: checkTokenPermissions,
			Kind:  kind,
			Name:  signalName,
			Value: scope.Value.Value,
			Path:  path,
			Line:  posLine(scope.Value.Pos),
		})
	}
	return signals
}

func sortedWorkflowJobIDs(workflow *actionlint.Workflow) []string {
	ids := make([]string, 0, len(workflow.Jobs))
	for id := range workflow.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func workflowJobName(job *actionlint.Job) string {
	if job.Name != nil && job.Name.Value != "" {
		return job.Name.Value
	}
	if job.ID != nil {
		return job.ID.Value
	}
	return ""
}

func posLine(pos *actionlint.Pos) uint {
	if pos == nil || pos.Line < 1 {
		return 0
	}
	return uint(pos.Line)
}

func (d *localDetectors) runWorkflows(
	tree fs.FS,
	changes []githistory.Change,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorWorkflows]
	if !run {
		detectorStats.skipped++
		return
	}
	recordDetectorRun(detectorStats, forceFull)
	started := time.Now()

	var signals []Signal
	var paths []string
	var err error
	if forceFull {
		signals, err = allWorkflowSignals(tree, d.shell)
	} else {
		signals, paths, err = workflowSignalsForChanges(tree, changes, d.workflowCache, d.shell)
	}
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorWorkflows] = err.Error()
		return
	}

	delete(current.errors, detectorWorkflows)
	if forceFull {
		removeCheckSignals(current.signals, checkArtifactProvenance)
		removeCheckSignals(current.signals, checkDangerousWorkflow)
		removeCheckSignals(current.signals, checkTokenPermissions)
		removeCheckSignals(current.signals, checkCacheMode)
		removeCheckSignals(current.signals, checkJobTimeout)
		removeCheckSignals(current.signals, checkPackaging)
		removeWorkflowCheckSignals(current.signals, checkPackageProvenance)
		removeCheckSignals(current.signals, checkRunnerSelection)
		removeWorkflowCheckSignals(current.signals, checkSAST)
		removeWorkflowCheckSignals(current.signals, checkShellDependency)
	} else {
		pathSet := make(map[string]bool, len(paths))
		for _, path := range paths {
			pathSet[path] = true
		}
		removePathSignals(current.signals, checkDangerousWorkflow, pathSet)
		removePathSignals(current.signals, checkArtifactProvenance, pathSet)
		removePathSignals(current.signals, checkTokenPermissions, pathSet)
		removePathSignals(current.signals, checkCacheMode, pathSet)
		removePathSignals(current.signals, checkJobTimeout, pathSet)
		removePathSignals(current.signals, checkPackaging, pathSet)
		removePathSignals(current.signals, checkPackageProvenance, pathSet)
		removePathSignals(current.signals, checkRunnerSelection, pathSet)
		removePathSignals(current.signals, checkSAST, pathSet)
		removePathSignals(current.signals, checkShellDependency, pathSet)
	}
	addSignals(current.signals, signals)
}

func removeWorkflowCheckSignals(signals map[string]Signal, check string) {
	for key, signal := range signals {
		if signal.Check == check && isWorkflowPath(signal.Path) {
			delete(signals, key)
		}
	}
}
