package main

import (
	"strings"
	"testing"
)

const (
	testChangelogPath          = "CHANGELOG.md"
	testSecurityChangelogEntry = "Reject unsafe archive paths"
)

func TestSecurityChangelogSignals(t *testing.T) {
	t.Parallel()

	signals, err := securityChangelogSignals(testChangelogPath, strings.NewReader(`# 2.0.0

## Security fixes

- `+testSecurityChangelogEntry+`
- Fix CVE-2026-12345 in the parser
- No known vulnerabilities

### Hardening

1. Restrict temporary-file permissions

## Changed

- Update the security policy link
- Fix GHSA-2345-cfgh-jmpq
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []Signal{
		{Check: checkSecurityChangelog, Kind: signalKindChangelogEntry, Value: testSecurityChangelogEntry, Path: testChangelogPath},
		{Check: checkSecurityChangelog, Kind: signalKindChangelogEntry, Value: "Restrict temporary-file permissions", Path: testChangelogPath},
		{Check: checkSecurityChangelog, Kind: signalKindChangelogEntry, Value: "Update the security policy link", Path: testChangelogPath},
		{Check: checkSecurityChangelog, Kind: signalKindAdvisory, Name: "CVE-2026-12345", Value: "Fix CVE-2026-12345 in the parser", Path: testChangelogPath},
		{Check: checkSecurityChangelog, Kind: signalKindAdvisory, Name: "GHSA-2345-CFGH-JMPQ", Value: "Fix GHSA-2345-cfgh-jmpq", Path: testChangelogPath},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("missing %#v in %#v", wanted, signals)
		}
	}
	if len(signals) != 5 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestSecurityChangelogSignalsIgnoresHeadingsAndUnrelatedEntries(t *testing.T) {
	t.Parallel()

	signals, err := securityChangelogSignals("NEWS.md", strings.NewReader(`# Security

# Changed

- Improve parser performance

# Food insecurity data

- Refresh population sample
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestSecurityChangelogSignalsSupportsUnderlinedHeadings(t *testing.T) {
	t.Parallel()

	signals, err := securityChangelogSignals("CHANGES.rst", strings.NewReader(`2.0.0
=====

Security
--------

- `+testSecurityChangelogEntry+`

Hardening
~~~~~~~~~

- Restrict temporary-file permissions

Fixed
-----

- Improve parser performance
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []Signal{
		{Check: checkSecurityChangelog, Kind: signalKindChangelogEntry, Value: testSecurityChangelogEntry, Path: "CHANGES.rst"},
		{Check: checkSecurityChangelog, Kind: signalKindChangelogEntry, Value: "Restrict temporary-file permissions", Path: "CHANGES.rst"},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("missing %#v in %#v", wanted, signals)
		}
	}
	if len(signals) != 2 {
		t.Fatalf("signals = %#v", signals)
	}
}
