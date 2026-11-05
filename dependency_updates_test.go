package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestDependabotSignalsDescribeUpdatePolicy(t *testing.T) {
	signals := dependabotSignals(".github/dependabot.yml", []byte(`
version: 2
updates:
  - package-ecosystem: npm
    directories:
      - /frontend
      - /admin
    schedule:
      interval: weekly
      day: tuesday
    open-pull-requests-limit: 5
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: daily
`))

	npm := findSignal(t, signals, "Dependabot", "npm")
	for _, want := range []string{
		"directories=/frontend,/admin",
		"schedule=weekly/tuesday",
		"open-pull-requests=5",
		"config=sha256:",
	} {
		if !strings.Contains(npm.Value, want) {
			t.Errorf("npm value %q does not contain %q", npm.Value, want)
		}
	}
	gomod := findSignal(t, signals, "Dependabot", "gomod")
	if !strings.Contains(gomod.Value, "directory=/; schedule=daily") {
		t.Errorf("gomod value = %q", gomod.Value)
	}
}

func TestDependabotConfigDigestIgnoresFormatting(t *testing.T) {
	first := dependabotSignals(".github/dependabot.yml", []byte(`
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
`))
	second := dependabotSignals(".github/dependabot.yml", []byte(`
updates: [{schedule: {interval: weekly}, directory: /, package-ecosystem: npm}]
version: 2
`))

	if first[0].Value != second[0].Value {
		t.Fatalf("config digests differ: %q != %q", first[0].Value, second[0].Value)
	}
	if first[1].Value != second[1].Value {
		t.Fatalf("update summaries differ: %q != %q", first[1].Value, second[1].Value)
	}
}

func TestDependencyUpdateConfigSignalsParsesRenovateJSONC(t *testing.T) {
	signals, err := dependencyUpdateConfigSignals(fstest.MapFS{
		"renovate.jsonc": {Data: []byte(`{
          // Keep JavaScript and Go dependencies current.
          "enabledManagers": ["npm", "gomod"],
          "schedule": ["before 5am on monday"],
          "dependencyDashboard": true,
        }`)},
	})
	if err != nil {
		t.Fatalf("dependencyUpdateConfigSignals: %v", err)
	}

	config := findSignal(t, signals, "Renovate", "config")
	for _, want := range []string{
		"enabled-managers=gomod,npm",
		"schedule=before 5am on monday",
		"dependencyDashboard=true",
		"config=sha256:",
	} {
		if !strings.Contains(config.Value, want) {
			t.Errorf("Renovate config value %q does not contain %q", config.Value, want)
		}
	}
	if manager := findSignal(t, signals, "Renovate", "npm"); manager.Value != "enabled" {
		t.Errorf("npm manager value = %q, want enabled", manager.Value)
	}
}

func TestDependencyUpdateConfigSignalsReadsPackageJSON(t *testing.T) {
	signals, err := dependencyUpdateConfigSignals(fstest.MapFS{
		packageJSONPath: {Data: []byte(`{
          "name": "example",
          "renovate": {"enabledManagers": ["cargo"]}
        }`)},
	})
	if err != nil {
		t.Fatalf("dependencyUpdateConfigSignals: %v", err)
	}

	manager := findSignal(t, signals, "Renovate", "cargo")
	if manager.Path != packageJSONPath {
		t.Errorf("manager path = %q, want package.json", manager.Path)
	}
}

func TestDependencyUpdateConfigSignalsRecordsUnparsedJSON5(t *testing.T) {
	signals, err := dependencyUpdateConfigSignals(fstest.MapFS{
		"renovate.json5": {Data: []byte(`{enabledManagers: ['npm']}`)},
	})
	if err != nil {
		t.Fatalf("dependencyUpdateConfigSignals: %v", err)
	}

	config := findSignal(t, signals, "Renovate", "config")
	if !strings.HasPrefix(config.Value, "unparsed sha256:") {
		t.Errorf("unparsed config value = %q", config.Value)
	}
}

func findSignal(t *testing.T, signals []Signal, kind, name string) Signal {
	t.Helper()
	for _, signal := range signals {
		if signal.Kind == kind && signal.Name == name {
			return signal
		}
	}
	t.Fatalf("signal %s/%s not found: %#v", kind, name, signals)
	return Signal{}
}
