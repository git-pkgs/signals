package main

import (
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	gitchangelog "github.com/git-pkgs/changelog"
)

const changelogValueRunes = 512

var (
	securityChangelogTermPattern = regexp.MustCompile(`(?i)\b(?:security|vulnerabilit(?:y|ies)|CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b`)
	securityAdvisoryPattern      = regexp.MustCompile(`(?i)\b(?:CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b`)
	securitySectionPattern       = regexp.MustCompile(`(?i)\b(?:security|vulnerabilit(?:y|ies))\b`)
)

func securityChangelogSignals(filePath string, reader io.Reader) ([]Signal, error) {
	parser := securityChangelogParser{filePath: filePath}
	scanner := gitchangelog.NewBlockScanner(reader)
	for scanner.Scan() {
		parser.addBlock(scanner.Block())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sortSignals(parser.signals)
	return deduplicateSignals(parser.signals), nil
}

type securityChangelogParser struct {
	filePath      string
	securityLevel int
	signals       []Signal
}

func (parser *securityChangelogParser) addBlock(block gitchangelog.Block) {
	if block.Kind == gitchangelog.BlockHeading {
		parser.addHeading(block.Level, block.Text)
		return
	}

	entry := block.Text
	advisories := securityAdvisorySignals(parser.filePath, entry)
	if len(advisories) > 0 {
		parser.signals = append(parser.signals, advisories...)
		return
	}
	if !usefulChangelogSectionEntry(entry) {
		return
	}
	if (parser.securityLevel > 0 && block.Kind == gitchangelog.BlockListItem) || usefulSecurityChangelogEntry(entry) {
		parser.signals = append(parser.signals, Signal{
			Check: checkSecurityChangelog,
			Kind:  signalKindChangelogEntry,
			Value: truncateChangelogValue(entry),
			Path:  parser.filePath,
		})
	}
}

func (parser *securityChangelogParser) addHeading(level int, heading string) {
	if parser.securityLevel > 0 && level <= parser.securityLevel {
		parser.securityLevel = 0
	}
	if securitySectionHeading(heading) {
		parser.securityLevel = level
	}
	parser.signals = append(parser.signals, securityAdvisorySignals(parser.filePath, heading)...)
}

func securityAdvisorySignals(filePath, entry string) []Signal {
	matches := securityAdvisoryPattern.FindAllString(entry, -1)
	signals := make([]Signal, 0, len(matches))
	for _, advisory := range matches {
		signals = append(signals, Signal{
			Check: checkSecurityChangelog,
			Kind:  signalKindAdvisory,
			Name:  strings.ToUpper(advisory),
			Value: truncateChangelogValue(entry),
			Path:  filePath,
		})
	}
	return signals
}

func securitySectionHeading(heading string) bool {
	return securitySectionPattern.MatchString(heading)
}

func usefulSecurityChangelogEntry(entry string) bool {
	if !securityChangelogTermPattern.MatchString(entry) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(entry)) {
	case "security", "security fixes", "security updates", "vulnerability", "vulnerabilities":
		return false
	default:
		return true
	}
}

func usefulChangelogSectionEntry(entry string) bool {
	switch strings.ToLower(strings.TrimSpace(entry)) {
	case "", "n/a", "none", "no changes", "no known vulnerabilities", "no security changes":
		return false
	default:
		return true
	}
}

func truncateChangelogValue(value string) string {
	if utf8.RuneCountInString(value) <= changelogValueRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:changelogValueRunes])
}
