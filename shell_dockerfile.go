package main

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var dockerfileHeredocPattern = regexp.MustCompile(`(?:^|[^<])<<-?\s*(?:'([^']+)'|"([^"]+)"|([A-Za-z0-9_.-]+))`)

type dockerfileScript struct {
	content string
	line    uint
}

func (a *shellAnalyzer) dockerfileSignals(filePath string, data []byte) []Signal {
	var combined strings.Builder
	line := uint(1)
	for _, instruction := range dockerfileRunScripts(data) {
		if !shellScriptParses(instruction.content) {
			continue
		}
		for line < instruction.line {
			combined.WriteByte('\n')
			line++
		}
		combined.WriteString(instruction.content)
		line += uint(strings.Count(instruction.content, "\n"))
		combined.WriteByte('\n')
		line++
	}
	return a.scriptSignals(filePath, []byte(combined.String()), 0)
}

func shellScriptParses(content string) bool {
	_, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(content), "")
	return err == nil
}

func dockerfileRunScripts(data []byte) []dockerfileScript {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var scripts []dockerfileScript
	var logical strings.Builder
	var heredoc strings.Builder
	var heredocDelimiter string
	var heredocLine uint
	var startLine uint
	line := uint(0)
	for scanner.Scan() {
		line++
		text := scanner.Text()
		trimmed := strings.TrimSpace(text)
		if heredocDelimiter != "" {
			if trimmed == heredocDelimiter {
				scripts = append(scripts, dockerfileScript{content: heredoc.String(), line: heredocLine})
				heredoc.Reset()
				heredocDelimiter = ""
				continue
			}
			if heredoc.Len() > 0 {
				heredoc.WriteByte('\n')
			}
			heredoc.WriteString(text)
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if logical.Len() > 0 {
				logical.WriteString("\\\n")
			}
			continue
		}
		if logical.Len() == 0 {
			startLine = line
		}
		if strings.HasSuffix(trimmed, "\\") {
			logical.WriteString(trimmed)
			logical.WriteByte('\n')
			continue
		}
		logical.WriteString(text)
		instruction := strings.TrimSpace(logical.String())
		logical.Reset()
		command, ok := dockerfileRunCommand(instruction)
		if !ok {
			continue
		}
		if delimiter := dockerfileHeredoc(command); delimiter != "" {
			heredocDelimiter = delimiter
			heredocLine = line + 1
			continue
		}
		scripts = append(scripts, dockerfileScript{content: command, line: startLine})
	}
	return scripts
}

func dockerfileRunCommand(instruction string) (string, bool) {
	if len(instruction) < 4 || !strings.EqualFold(instruction[:3], "run") ||
		!strings.ContainsAny(instruction[3:4], " \t") {
		return "", false
	}
	command := strings.TrimSpace(instruction[4:])
	for strings.HasPrefix(command, "--") {
		_, rest, ok := strings.Cut(command, " ")
		if !ok {
			return "", false
		}
		command = strings.TrimSpace(rest)
	}
	return command, command != "" && !strings.HasPrefix(command, "[")
}

func dockerfileHeredoc(command string) string {
	match := dockerfileHeredocPattern.FindStringSubmatch(command)
	if match == nil {
		return ""
	}
	for _, delimiter := range match[1:] {
		if delimiter != "" {
			return delimiter
		}
	}
	return ""
}
