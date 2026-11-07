package main

import (
	"path"
	"strings"

	actionlint "actionlint.kjanat.dev"
)

const (
	packageProvenanceNPMEnv      = "npm-environment"
	packageProvenanceNPMFlag     = "npm-flag"
	packageProvenancePyPITrusted = "pypi-oidc"
)

var pypiCredentialEnvironment = []string{
	"UV_PUBLISH_PASSWORD",
	"UV_PUBLISH_TOKEN",
	"UV_PUBLISH_USERNAME",
}

func packageProvenanceSignals(filePath string, workflow *actionlint.Workflow) []Signal {
	var signals []Signal
	for _, id := range sortedWorkflowJobIDs(workflow) {
		job := workflow.Jobs[id]
		if job == nil {
			continue
		}
		jobName := workflowJobName(job)
		idToken := jobHasIDTokenWrite(workflow, job)
		walkWorkflowSteps(job.Steps, func(step *actionlint.Step) {
			envs := []*actionlint.Env{workflow.Env, job.Env, step.Env}
			switch execution := step.Exec.(type) {
			case *actionlint.ExecAction:
				if idToken && pypiTrustedPublishingAction(execution) {
					signals = append(signals, Signal{
						Check: checkPackageProvenance,
						Kind:  packageProvenancePyPITrusted,
						Name:  jobName,
						Value: pypiPublishAction,
						Path:  filePath,
					})
				}
			case *actionlint.ExecRun:
				if execution == nil || execution.Run == nil {
					return
				}
				signals = append(signals, packageProvenanceCommandSignals(
					filePath,
					jobName,
					execution.Run.Value,
					envs,
					idToken,
				)...)
			}
		})
	}
	return signals
}

func packageProvenanceCommandSignals(
	filePath, jobName, script string,
	envs []*actionlint.Env,
	idToken bool,
) []Signal {
	var signals []Signal
	for _, line := range strings.Split(script, "\n") {
		for _, segment := range commandSegments(line) {
			fields := strings.Fields(segment)
			client, args := npmPublishCommand(fields)
			if client != "" {
				inlineProvenance, inline := inlineEnvValue(fields, "NPM_CONFIG_PROVENANCE")
				flagEnabled, flagDeclared := npmProvenanceFlag(args)
				switch {
				case flagDeclared:
					if flagEnabled {
						signals = append(signals, packageProvenanceSignal(
							filePath, jobName, packageProvenanceNPMFlag, client,
						))
					}
				case inline && strings.EqualFold(inlineProvenance, "true") ||
					!inline && effectiveEnvTrue(envs, "NPM_CONFIG_PROVENANCE"):
					signals = append(signals, packageProvenanceSignal(
						filePath, jobName, packageProvenanceNPMEnv, client,
					))
				}
			}
			if idToken && uvTrustedPublishingCommand(fields) &&
				!hasInlineEnvironment(fields, pypiCredentialEnvironment) &&
				!hasEffectiveEnvironment(envs, pypiCredentialEnvironment) {
				signals = append(signals, packageProvenanceSignal(
					filePath, jobName, packageProvenancePyPITrusted, "uv",
				))
			}
		}
	}
	return signals
}

func packageProvenanceSignal(filePath, jobName, kind, value string) Signal {
	return Signal{
		Check: checkPackageProvenance,
		Kind:  kind,
		Name:  jobName,
		Value: value,
		Path:  filePath,
	}
}

func npmPublishCommand(fields []string) (string, []string) {
	fields = unwrapCommand(fields)
	if len(fields) < minimumPackagingFields {
		return "", nil
	}
	client := path.Base(fields[0])
	args := fields[1:]
	switch client {
	case packagingNameNPM, "pnpm":
		if args[0] == packagingKindPublish {
			return client, args[1:]
		}
	case "yarn":
		if len(args) > 1 && args[0] == packagingNameNPM && args[1] == "publish" {
			return client, args[2:]
		}
	}
	return "", nil
}

func npmProvenanceFlag(args []string) (enabled, declared bool) {
	for _, arg := range args {
		if arg == "--provenance" {
			enabled = true
			declared = true
			continue
		}
		if arg == "--no-provenance" {
			enabled = false
			declared = true
			continue
		}
		if value, ok := strings.CutPrefix(arg, "--provenance="); ok {
			enabled = strings.EqualFold(value, "true")
			declared = true
		}
	}
	return enabled, declared
}

func inlineEnvValue(fields []string, name string) (string, bool) {
	var result string
	var found bool
	for _, field := range fields {
		if field == "env" || field == "sudo" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return result, found
		}
		if strings.EqualFold(key, name) {
			result = value
			found = true
		}
	}
	return result, found
}

func effectiveEnvTrue(envs []*actionlint.Env, name string) bool {
	value, ok := effectiveEnvValue(envs, name)
	return ok && strings.EqualFold(value, "true")
}

func effectiveEnvValue(envs []*actionlint.Env, name string) (string, bool) {
	var value string
	var found bool
	for _, env := range envs {
		if env == nil {
			continue
		}
		if env.Expression != nil {
			found = false
			continue
		}
		for key, variable := range env.Vars {
			if !strings.EqualFold(key, name) || variable == nil || variable.Value == nil {
				continue
			}
			value = strings.TrimSpace(variable.Value.Value)
			found = true
		}
	}
	return value, found
}

func hasEffectiveEnvironment(envs []*actionlint.Env, names []string) bool {
	for _, env := range envs {
		if env != nil && env.Expression != nil {
			return true
		}
	}
	for _, name := range names {
		if value, ok := effectiveEnvValue(envs, name); ok && value != "" {
			return true
		}
	}
	return false
}

func hasInlineEnvironment(fields []string, names []string) bool {
	for _, name := range names {
		if _, ok := inlineEnvValue(fields, name); ok {
			return true
		}
	}
	return false
}

func jobHasIDTokenWrite(workflow *actionlint.Workflow, job *actionlint.Job) bool {
	permissions := job.Permissions
	if permissions == nil {
		permissions = workflow.Permissions
	}
	if permissions == nil {
		return false
	}
	if permissions.All != nil && strings.EqualFold(permissions.All.Value, "write-all") {
		return true
	}
	scope := permissions.Scopes["id-token"]
	return scope != nil && scope.Value != nil && strings.EqualFold(scope.Value.Value, "write")
}

func pypiTrustedPublishingAction(execution *actionlint.ExecAction) bool {
	if execution == nil || execution.Uses == nil || execution.InputsExpression != nil {
		return false
	}
	action, _, _ := strings.Cut(strings.TrimPrefix(strings.ToLower(execution.Uses.Value), "actions://"), "@")
	return action == pypiPublishAction && inputValue(execution.Inputs, "password") == ""
}

func uvTrustedPublishingCommand(fields []string) bool {
	fields = unwrapCommand(fields)
	if len(fields) < 2 || path.Base(fields[0]) != "uv" || fields[1] != packagingKindPublish {
		return false
	}
	args := fields[2:]
	for index, field := range args {
		for _, option := range []string{"--password", "--token", "--username"} {
			if field == option || strings.HasPrefix(field, option+"=") {
				return false
			}
		}
		for _, option := range []string{"-p", "-t", "-u"} {
			if strings.HasPrefix(field, option) {
				return false
			}
		}
		if strings.EqualFold(field, "--trusted-publishing=never") ||
			field == "--trusted-publishing" && index+1 < len(args) &&
				strings.EqualFold(args[index+1], "never") {
			return false
		}
	}
	return true
}
