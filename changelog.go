package main

import (
	"bufio"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	changelogUnderlineMinLength = 3
	changelogValueRunes         = 512
)

var (
	securityChangelogTermPattern = regexp.MustCompile(`(?i)\b(?:security|vulnerabilit(?:y|ies)|CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b`)
	securityAdvisoryPattern      = regexp.MustCompile(`(?i)\b(?:CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b`)
	securitySectionPattern       = regexp.MustCompile(`(?i)\b(?:security|vulnerabilit(?:y|ies))\b`)
)

func securityChangelogSignals(filePath string, reader io.Reader) ([]Signal, error) {
	parser := securityChangelogParser{filePath: filePath}
	var pending string
	buffered := bufio.NewReader(reader)
	for {
		text, err := buffered.ReadString('\n')
		line := strings.TrimSpace(text)
		if line == "" {
			parser.addLine(pending)
			pending = ""
		} else if level, isUnderline := changelogUnderlineHeading(line); isUnderline && changelogHeadingCandidate(pending) {
			parser.addHeading(level, pending)
			pending = ""
		} else {
			parser.addLine(pending)
			pending = line
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, err
			}
			break
		}
	}
	parser.addLine(pending)
	sortSignals(parser.signals)
	return deduplicateSignals(parser.signals), nil
}

type securityChangelogParser struct {
	filePath      string
	securityLevel int
	signals       []Signal
}

func (parser *securityChangelogParser) addLine(line string) {
	if line == "" {
		return
	}
	level, heading, isHeading := changelogHeading(line)
	if isHeading {
		parser.addHeading(level, heading)
		return
	}

	entry := changelogEntry(line)
	advisories := securityAdvisorySignals(parser.filePath, entry)
	if len(advisories) > 0 {
		parser.signals = append(parser.signals, advisories...)
		return
	}
	if !usefulChangelogSectionEntry(entry) {
		return
	}
	if (parser.securityLevel > 0 && changelogListEntry(line)) || usefulSecurityChangelogEntry(entry) {
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

func changelogHeading(line string) (int, string, bool) {
	marker := line[0]
	if marker != '#' && marker != '=' {
		return 0, "", false
	}
	level := 0
	for level < len(line) && line[level] == marker {
		level++
	}
	if level == len(line) || !unicode.IsSpace(rune(line[level])) {
		return 0, "", false
	}
	return level, strings.TrimSpace(line[level:]), true
}

func changelogUnderlineHeading(line string) (int, bool) {
	if len(line) < changelogUnderlineMinLength {
		return 0, false
	}
	level := strings.IndexByte("=-~^", line[0]) + 1
	if level == 0 {
		return 0, false
	}
	for index := 1; index < len(line); index++ {
		if line[index] != line[0] {
			return 0, false
		}
	}
	return level, true
}

func changelogHeadingCandidate(line string) bool {
	return line != "" && !changelogListEntry(line) && !strings.HasPrefix(line, ".. ")
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

func changelogListEntry(line string) bool {
	if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "+ ") {
		return true
	}
	marker, _, found := strings.Cut(line, " ")
	if !found {
		return false
	}
	if !strings.HasSuffix(marker, ".") && !strings.HasSuffix(marker, ")") {
		return false
	}
	marker = strings.TrimSuffix(strings.TrimSuffix(marker, "."), ")")
	return marker != "" && strings.IndexFunc(marker, func(char rune) bool { return !unicode.IsDigit(char) }) == -1
}

func changelogEntry(line string) string {
	line = strings.TrimSpace(line)
	if changelogListEntry(line) {
		_, entry, _ := strings.Cut(line, " ")
		return strings.TrimSpace(entry)
	}
	return line
}

func truncateChangelogValue(value string) string {
	if utf8.RuneCountInString(value) <= changelogValueRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:changelogValueRunes])
}
