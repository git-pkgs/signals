package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/tidwall/jsonc"
	"github.com/titanous/json5"
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
	Version              int                                      `yaml:"version"`
	MultiEcosystemGroups map[string]dependabotMultiEcosystemGroup `yaml:"multi-ecosystem-groups"`
	Updates              []dependabotUpdate                       `yaml:"updates"`
}

type dependabotSchedule struct {
	Interval string `yaml:"interval"`
	Day      string `yaml:"day"`
	Time     string `yaml:"time"`
	Timezone string `yaml:"timezone"`
	Cronjob  string `yaml:"cronjob"`
}

type dependabotCooldown struct {
	DefaultDays     *int `yaml:"default-days"`
	SemverMajorDays *int `yaml:"semver-major-days"`
	SemverMinorDays *int `yaml:"semver-minor-days"`
	SemverPatchDays *int `yaml:"semver-patch-days"`
}

type dependabotMultiEcosystemGroup struct {
	Schedule dependabotSchedule `yaml:"schedule"`
	digest   string
}

type dependabotUpdate struct {
	PackageEcosystem      string             `yaml:"package-ecosystem"`
	Directory             string             `yaml:"directory"`
	Directories           []string           `yaml:"directories"`
	TargetBranch          string             `yaml:"target-branch"`
	OpenPullRequestsLimit *int               `yaml:"open-pull-requests-limit"`
	MultiEcosystemGroup   string             `yaml:"multi-ecosystem-group"`
	Schedule              dependabotSchedule `yaml:"schedule"`
	Cooldown              dependabotCooldown `yaml:"cooldown"`
	digest                string
}

func (g *dependabotMultiEcosystemGroup) UnmarshalYAML(node *yaml.Node) error {
	type plain dependabotMultiEcosystemGroup
	var parsed plain
	if err := node.Decode(&parsed); err != nil {
		return err
	}
	*g = dependabotMultiEcosystemGroup(parsed)

	var raw any
	if err := node.Decode(&raw); err != nil {
		return err
	}
	g.digest = semanticDigest(raw)
	return nil
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
	groupNames := make([]string, 0, len(config.MultiEcosystemGroups))
	for name := range config.MultiEcosystemGroups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for _, name := range groupNames {
		signals = append(signals, Signal{
			Check: checkDependencyUpdateConfig,
			Kind:  dependencyToolDependabot,
			Name:  "group:" + name,
			Value: dependabotMultiEcosystemGroupSummary(config.MultiEcosystemGroups[name]),
			Path:  path,
		})
	}
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
	if update.MultiEcosystemGroup != "" {
		parts = append(parts, "multi-ecosystem-group="+update.MultiEcosystemGroup)
	}
	parts = append(parts, dependabotScheduleSummary(update.Schedule)...)
	if update.TargetBranch != "" {
		parts = append(parts, "target="+update.TargetBranch)
	}
	if update.OpenPullRequestsLimit != nil {
		parts = append(parts, "open-pull-requests="+strconv.Itoa(*update.OpenPullRequestsLimit))
	}
	if cooldown := dependabotCooldownSummary(update.Cooldown); cooldown != "" {
		parts = append(parts, "cooldown="+cooldown)
	}
	parts = append(parts, "config="+update.digest)
	return strings.Join(parts, "; ")
}

func dependabotMultiEcosystemGroupSummary(group dependabotMultiEcosystemGroup) string {
	parts := dependabotScheduleSummary(group.Schedule)
	parts = append(parts, "config="+group.digest)
	return strings.Join(parts, "; ")
}

func dependabotScheduleSummary(schedule dependabotSchedule) []string {
	var parts []string
	if schedule.Interval != "" {
		value := schedule.Interval
		for _, detail := range []string{schedule.Day, schedule.Time, schedule.Timezone} {
			if detail != "" {
				value += "/" + detail
			}
		}
		parts = append(parts, "schedule="+value)
	}
	if schedule.Cronjob != "" {
		parts = append(parts, "cronjob="+schedule.Cronjob)
	}
	return parts
}

func dependabotCooldownSummary(cooldown dependabotCooldown) string {
	values := []struct {
		name string
		days *int
	}{
		{name: "default-days", days: cooldown.DefaultDays},
		{name: "semver-major-days", days: cooldown.SemverMajorDays},
		{name: "semver-minor-days", days: cooldown.SemverMinorDays},
		{name: "semver-patch-days", days: cooldown.SemverPatchDays},
	}
	var parts []string
	for _, value := range values {
		if value.days != nil {
			parts = append(parts, value.name+":"+strconv.Itoa(*value.days))
		}
	}
	return strings.Join(parts, ",")
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
	if path == packageJSONPath {
		return parseRenovatePackageJSON(data)
	}
	if len(data) == 0 {
		data = []byte("{}")
	}

	var config map[string]any
	if strings.HasSuffix(path, ".json5") {
		if err := json5.Unmarshal(data, &config); err != nil {
			return nil, false
		}
		return config, true
	}

	data = jsonc.ToJSON(data)
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, false
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, false
	}
	return config, true
}

func parseRenovatePackageJSON(data []byte) (map[string]any, bool) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, false
	}
	embedded, found := document["renovate"]
	if !found {
		return nil, false
	}

	var config map[string]any
	if err := json.Unmarshal(embedded, &config); err == nil {
		return config, true
	}
	var preset string
	if err := json.Unmarshal(embedded, &preset); err == nil && preset != "" {
		return map[string]any{"extends": []any{preset}}, true
	}
	return nil, false
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
	if presets := stringSlice(config["extends"]); len(presets) > 0 {
		parts = append(parts, "extends="+strings.Join(presets, ","))
	}
	if age, ok := config["minimumReleaseAge"].(string); ok && age != "" {
		parts = append(parts, "minimumReleaseAge="+age)
	}
	if ages := renovatePackageRuleMinimumReleaseAges(config); len(ages) > 0 {
		parts = append(parts, "packageRules.minimumReleaseAge="+strings.Join(ages, ","))
	}
	for _, option := range []string{"enabled", "automerge", "dependencyDashboard"} {
		if value, ok := config[option].(bool); ok {
			parts = append(parts, option+"="+strconv.FormatBool(value))
		}
	}
	parts = append(parts, "config="+semanticDigest(config))
	return strings.Join(parts, "; ")
}

func renovatePackageRuleMinimumReleaseAges(config map[string]any) []string {
	rules, ok := config["packageRules"].([]any)
	if !ok {
		return nil
	}
	unique := make(map[string]bool)
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if age, ok := rule["minimumReleaseAge"].(string); ok && age != "" {
			unique[age] = true
		}
	}
	ages := make([]string, 0, len(unique))
	for age := range unique {
		ages = append(ages, age)
	}
	sort.Strings(ages)
	return ages
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := readUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values")
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			token, err = decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if keys[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = true
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
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
