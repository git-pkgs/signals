package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/tidwall/jsonc"
	"go.yaml.in/yaml/v3"
)

const (
	checkDependencyUpdateConfig = "Dependency-Update-Config"
	dependencyToolDependabot    = "Dependabot"
	dependencyToolRenovate      = "Renovate"
	dependabotYMLPath           = ".github/dependabot.yml"
	dependabotYAMLPath          = ".github/dependabot.yaml"
	packageJSONPath             = "package.json"
)

var renovateConfigPaths = []string{
	"renovate.json",
	"renovate.jsonc",
	"renovate.json5",
	".github/renovate.json",
	".github/renovate.jsonc",
	".github/renovate.json5",
	".gitlab/renovate.json",
	".gitlab/renovate.jsonc",
	".gitlab/renovate.json5",
	".renovaterc",
	".renovaterc.json",
	".renovaterc.jsonc",
	".renovaterc.json5",
	packageJSONPath,
}

type dependabotConfig struct {
	Version int                `yaml:"version"`
	Updates []dependabotUpdate `yaml:"updates"`
}

type dependabotUpdate struct {
	PackageEcosystem      string   `yaml:"package-ecosystem"`
	Directory             string   `yaml:"directory"`
	Directories           []string `yaml:"directories"`
	TargetBranch          string   `yaml:"target-branch"`
	OpenPullRequestsLimit *int     `yaml:"open-pull-requests-limit"`
	Schedule              struct {
		Interval string `yaml:"interval"`
		Day      string `yaml:"day"`
		Time     string `yaml:"time"`
		Timezone string `yaml:"timezone"`
	} `yaml:"schedule"`
	digest string
}

func (u *dependabotUpdate) UnmarshalYAML(node *yaml.Node) error {
	type plain dependabotUpdate
	var parsed plain
	if err := node.Decode(&parsed); err != nil {
		return err
	}
	*u = dependabotUpdate(parsed)

	var raw any
	if err := node.Decode(&raw); err != nil {
		return err
	}
	u.digest = semanticDigest(raw)
	return nil
}

func dependencyUpdateConfigSignals(tree fs.FS) ([]Signal, error) {
	var signals []Signal
	for _, path := range []string{dependabotYMLPath, dependabotYAMLPath} {
		data, found, err := readOptionalFile(tree, path)
		if err != nil {
			return nil, err
		}
		if found {
			signals = append(signals, dependabotSignals(path, data)...)
		}
	}

	renovate, err := findRenovateSignals(tree)
	if err != nil {
		return nil, err
	}
	signals = append(signals, renovate...)
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func dependabotSignals(path string, data []byte) []Signal {
	configSignal := Signal{
		Check: checkDependencyUpdateConfig,
		Kind:  dependencyToolDependabot,
		Name:  "config",
		Path:  path,
		Line:  1,
	}

	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		configSignal.Value = "invalid " + contentDigest(data)
		return []Signal{configSignal}
	}
	configSignal.Value = semanticDigest(raw)

	var config dependabotConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		configSignal.Value = "invalid " + configSignal.Value
		return []Signal{configSignal}
	}
	if config.Version != 0 {
		configSignal.Value = "version=" + strconv.Itoa(config.Version) + "; config=" + configSignal.Value
	}

	signals := []Signal{configSignal}
	for _, update := range config.Updates {
		signals = append(signals, Signal{
			Check: checkDependencyUpdateConfig,
			Kind:  dependencyToolDependabot,
			Name:  update.PackageEcosystem,
			Value: dependabotUpdateSummary(update),
			Path:  path,
		})
	}
	return signals
}

func dependabotUpdateSummary(update dependabotUpdate) string {
	var parts []string
	directories := update.Directories
	if update.Directory != "" {
		directories = []string{update.Directory}
	}
	if len(directories) == 1 {
		parts = append(parts, "directory="+directories[0])
	} else if len(directories) > 1 {
		parts = append(parts, "directories="+strings.Join(directories, ","))
	}
	if update.Schedule.Interval != "" {
		schedule := update.Schedule.Interval
		for _, detail := range []string{update.Schedule.Day, update.Schedule.Time, update.Schedule.Timezone} {
			if detail != "" {
				schedule += "/" + detail
			}
		}
		parts = append(parts, "schedule="+schedule)
	}
	if update.TargetBranch != "" {
		parts = append(parts, "target="+update.TargetBranch)
	}
	if update.OpenPullRequestsLimit != nil {
		parts = append(parts, "open-pull-requests="+strconv.Itoa(*update.OpenPullRequestsLimit))
	}
	parts = append(parts, "config="+update.digest)
	return strings.Join(parts, "; ")
}

func findRenovateSignals(tree fs.FS) ([]Signal, error) {
	for _, path := range renovateConfigPaths {
		data, found, err := readOptionalFile(tree, path)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}

		config, parsed := parseRenovateConfig(path, data)
		if path == packageJSONPath && !parsed {
			continue
		}
		return renovateSignals(path, data, config, parsed), nil
	}
	return nil, nil
}

func parseRenovateConfig(path string, data []byte) (map[string]any, bool) {
	var config map[string]any
	if err := json.Unmarshal(jsonc.ToJSON(data), &config); err != nil {
		return nil, false
	}
	if path != packageJSONPath {
		return config, true
	}

	embedded, ok := config["renovate"].(map[string]any)
	return embedded, ok
}

func renovateSignals(path string, data []byte, config map[string]any, parsed bool) []Signal {
	configSignal := Signal{
		Check: checkDependencyUpdateConfig,
		Kind:  dependencyToolRenovate,
		Name:  "config",
		Path:  path,
		Line:  1,
	}
	if !parsed {
		configSignal.Value = "unparsed " + contentDigest(data)
		return []Signal{configSignal}
	}

	configSignal.Value = renovateSummary(config)
	signals := []Signal{configSignal}
	for _, manager := range stringSlice(config["enabledManagers"]) {
		signals = append(signals, Signal{
			Check: checkDependencyUpdateConfig,
			Kind:  dependencyToolRenovate,
			Name:  manager,
			Value: "enabled",
			Path:  path,
			Line:  1,
		})
	}
	return signals
}

func renovateSummary(config map[string]any) string {
	var parts []string
	if managers := stringSlice(config["enabledManagers"]); len(managers) > 0 {
		sort.Strings(managers)
		parts = append(parts, "enabled-managers="+strings.Join(managers, ","))
	}
	if schedule := stringSlice(config["schedule"]); len(schedule) > 0 {
		parts = append(parts, "schedule="+strings.Join(schedule, ","))
	}
	for _, option := range []string{"enabled", "automerge", "dependencyDashboard"} {
		if value, ok := config[option].(bool); ok {
			parts = append(parts, option+"="+strconv.FormatBool(value))
		}
	}
	parts = append(parts, "config="+semanticDigest(config))
	return strings.Join(parts, "; ")
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok {
			values = append(values, value)
		}
	}
	return values
}

func semanticDigest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "sha256:unavailable"
	}
	return contentDigest(data)
}

func contentDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:6])
}

func readOptionalFile(tree fs.FS, path string) ([]byte, bool, error) {
	data, err := fs.ReadFile(tree, path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return data, true, nil
}

func dependencyUpdateConfigAffected(changes []string) bool {
	for _, changed := range changes {
		lower := strings.ToLower(changed)
		if lower == dependabotYMLPath || lower == dependabotYAMLPath {
			return true
		}
		for _, path := range renovateConfigPaths {
			if lower == strings.ToLower(path) {
				return true
			}
		}
	}
	return false
}
