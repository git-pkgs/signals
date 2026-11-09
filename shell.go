package main

import (
	"bytes"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const checkShellDependency = "Shell-Dependency"

const (
	shellKindChecksum       = "checksum-verification"
	shellKindDownload       = "download"
	shellKindDownloadAndRun = "download-and-run"
	shellKindPackageCommand = "package-command"
	shellOperationAdd       = "add"
	shellOperationInstall   = "install"
	shellOperationUpdate    = "update"
	shellStateUnverified    = "unverified"
	shellCommandCurl        = "curl"
	commandNameEnv          = "env"
	commandNamePython       = "python"
	commandNamePython3      = "python3"
	commandNameSudo         = "sudo"
	shellDownloadDynamic    = "dynamic"
)

var (
	shellDigestPattern   = regexp.MustCompile(`(?i)\b[0-9a-f]{32,128}\b`)
	shellChecksumTarget  = regexp.MustCompile(`(?i)\b[0-9a-f]{32,128}\s+\*?([^\s"']+)`)
	shellHexPathSegment  = regexp.MustCompile(`(?i)^[0-9a-f]{40,128}(?:\.[a-z0-9.]+)?$`)
	shellLanguageName    = map[string]bool{"bash": true, "dash": true, "ksh": true, "sh": true, "zsh": true}
	shellInterpreterName = map[string]bool{
		"node": true, "nodejs": true,
		"perl": true, "php": true, commandNamePython: true, "python2": true, commandNamePython3: true,
		"ruby": true,
	}
)

type shellAnalyzer struct {
	managerRules []shellManagerRule
}

type shellDownload struct {
	line           uint
	order          uint
	name           string
	state          string
	output         string
	executed       bool
	executionOrder uint
}

type shellChecksum struct {
	line      uint
	order     uint
	algorithm string
	target    string
	value     string
}

type shellExecution struct {
	order  uint
	target string
}

type shellAnalysis struct {
	analyzer       *shellAnalyzer
	filePath       string
	lineOffset     uint
	downloads      map[string]*shellDownload
	checksums      []shellChecksum
	executions     []shellExecution
	packageSignals []Signal
}

func (a *shellAnalyzer) scriptSignals(filePath string, data []byte, lineOffset uint) []Signal {
	if a == nil {
		return nil
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(bytes.NewReader(data), filePath)
	if err != nil {
		return nil
	}
	analysis := &shellAnalysis{
		analyzer:   a,
		filePath:   filePath,
		lineOffset: lineOffset,
		downloads:  make(map[string]*shellDownload),
	}
	syntax.Walk(file, analysis.walk)
	analysis.associateDownloads()
	return analysis.signals()
}

func (a *shellAnalysis) walk(node syntax.Node) bool {
	statement, ok := node.(*syntax.Stmt)
	if !ok {
		return true
	}
	switch command := statement.Cmd.(type) {
	case *syntax.CallExpr:
		a.collectCommand(statement)
	case *syntax.BinaryCmd:
		if command.Op.String() == "|" {
			a.collectPipeline(statement)
			return false
		}
	}
	return true
}

func (a *shellAnalysis) collectCommand(statement *syntax.Stmt) {
	args := normalizeShellCommand(shellStatementArgs(statement))
	if len(args) == 0 {
		return
	}
	line := a.lineOffset + statement.Pos().Line()
	order := statement.Pos().Offset()
	for _, download := range shellDownloads(args, statement, line) {
		mergeShellDownload(a.downloads, download)
	}
	if checksum, ok := shellChecksumCommand(args, line, order); ok {
		a.checksums = append(a.checksums, checksum)
	}
	if target, ok := shellExecutionTarget(args); ok {
		a.executions = append(a.executions, shellExecution{order: order, target: target})
	}
	if signal, ok := a.analyzer.packageCommandSignal(a.filePath, line, args); ok {
		a.packageSignals = append(a.packageSignals, signal)
	}
}

func (a *shellAnalysis) collectPipeline(statement *syntax.Stmt) {
	pipeline := shellPipelineStatements(statement)
	for _, item := range pipeline {
		a.collectCommand(item)
	}
	if len(pipeline) <= 1 {
		return
	}
	lastStatement := pipeline[len(pipeline)-1]
	last := normalizeShellCommand(shellStatementArgs(lastStatement))
	if shellInterpreterCommand(last) {
		a.markPipelineDownloadsExecuted(pipeline[:len(pipeline)-1])
	}
	previous := normalizeShellCommand(shellStatementArgs(pipeline[len(pipeline)-2]))
	a.setPipedChecksumTarget(
		last,
		previous,
		a.lineOffset+lastStatement.Pos().Line(),
		lastStatement.Pos().Offset(),
	)
}

func (a *shellAnalysis) markPipelineDownloadsExecuted(pipeline []*syntax.Stmt) {
	for _, item := range pipeline {
		args := normalizeShellCommand(shellStatementArgs(item))
		for _, download := range shellDownloads(args, item, a.lineOffset+item.Pos().Line()) {
			download.executed = true
			download.executionOrder = item.Pos().Offset()
			mergeShellDownload(a.downloads, download)
		}
	}
}

func (a *shellAnalysis) setPipedChecksumTarget(args, previous []string, line, order uint) {
	checksum, ok := shellChecksumCommand(args, line, order)
	if !ok {
		return
	}
	target := shellChecksumPipeTarget(previous)
	if target == "" {
		return
	}
	for index := len(a.checksums) - 1; index >= 0; index-- {
		if a.checksums[index].order == checksum.order && a.checksums[index].algorithm == checksum.algorithm {
			a.checksums[index].target = target
			a.checksums[index].value = target
			return
		}
	}
}

func (a *shellAnalysis) associateDownloads() {
	for _, download := range a.downloads {
		for _, execution := range a.executions {
			if download.output != "" && execution.order >= download.order &&
				sameShellPath(download.output, execution.target) {
				if !download.executed || execution.order < download.executionOrder {
					download.executed = true
					download.executionOrder = execution.order
				}
			}
		}
		for _, checksum := range a.checksums {
			if download.output != "" && checksum.target != "" &&
				checksum.order >= download.order && sameShellPath(download.output, checksum.target) &&
				(!download.executed || checksum.order <= download.executionOrder) {
				download.state = "checksum-verified"
			}
		}
	}
}

func (a *shellAnalysis) signals() []Signal {
	signals := make([]Signal, 0, len(a.downloads)+len(a.checksums)+len(a.packageSignals))
	for _, download := range a.downloads {
		kind := shellKindDownload
		if download.executed {
			kind = shellKindDownloadAndRun
		}
		signals = append(signals, Signal{
			Check: checkShellDependency,
			Kind:  kind,
			Name:  download.name,
			Value: download.state,
			Path:  a.filePath,
			Line:  download.line,
		})
	}
	for _, checksum := range a.checksums {
		signals = append(signals, Signal{
			Check: checkShellDependency,
			Kind:  shellKindChecksum,
			Name:  checksum.algorithm,
			Value: checksum.value,
			Path:  a.filePath,
			Line:  checksum.line,
		})
	}
	signals = append(signals, a.packageSignals...)
	sortSignals(signals)
	return deduplicateSignals(signals)
}

func shellCommandArgs(command *syntax.CallExpr) []string {
	if command == nil {
		return nil
	}
	args := make([]string, 0, len(command.Args))
	for _, word := range command.Args {
		if value, ok := shellWordValue(word); ok {
			args = append(args, value)
		}
	}
	return args
}

func shellStatementArgs(statement *syntax.Stmt) []string {
	if statement == nil {
		return nil
	}
	command, _ := statement.Cmd.(*syntax.CallExpr)
	return shellCommandArgs(command)
}

func shellPipelineStatements(statement *syntax.Stmt) []*syntax.Stmt {
	if statement == nil {
		return nil
	}
	binary, ok := statement.Cmd.(*syntax.BinaryCmd)
	if !ok || binary.Op.String() != "|" {
		return []*syntax.Stmt{statement}
	}
	return append(shellPipelineStatements(binary.X), shellPipelineStatements(binary.Y)...)
}

func shellWordValue(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var result strings.Builder
	for _, part := range word.Parts {
		switch value := part.(type) {
		case *syntax.Lit:
			result.WriteString(value.Value)
		case *syntax.SglQuoted:
			result.WriteString(value.Value)
		case *syntax.DblQuoted:
			for _, quoted := range value.Parts {
				switch nested := quoted.(type) {
				case *syntax.Lit:
					result.WriteString(nested.Value)
				case *syntax.ParamExp:
					if nested.Param != nil {
						result.WriteByte('$')
						result.WriteString(nested.Param.Value)
					}
				}
			}
		case *syntax.ParamExp:
			if value.Param != nil {
				result.WriteByte('$')
				result.WriteString(value.Param.Value)
			}
		default:
			return "", false
		}
	}
	return result.String(), result.Len() > 0
}

func normalizeShellCommand(args []string) []string {
	for len(args) > 0 {
		name := strings.ToLower(path.Base(args[0]))
		switch name {
		case "command", "exec":
			args = args[1:]
		case commandNameEnv, commandNameSudo:
			args = args[1:]
			for len(args) > 0 && (strings.HasPrefix(args[0], "-") || strings.Contains(args[0], "=")) {
				args = args[1:]
			}
		case commandNamePython, "python2", commandNamePython3:
			if len(args) > 2 && args[1] == "-m" {
				args = args[2:]
				continue
			}
			return args
		default:
			return args
		}
	}
	return args
}

func shellDownloads(args []string, statement *syntax.Stmt, line uint) []*shellDownload {
	if len(args) == 0 {
		return nil
	}
	command := strings.ToLower(path.Base(args[0]))
	if !shellDownloadCommand(command, args) {
		return nil
	}
	output := shellDownloadOutput(command, args, statement)
	var downloads []*shellDownload
	for _, argument := range args[1:] {
		name, state, ok := shellDownloadIdentity(argument)
		if !ok {
			continue
		}
		if name == shellDownloadDynamic {
			continue
		}
		downloads = append(downloads, &shellDownload{
			line: line, order: statement.Pos().Offset(), name: name, state: state, output: output,
		})
	}
	if len(downloads) == 0 {
		downloads = append(downloads, &shellDownload{
			line: line, order: statement.Pos().Offset(), name: shellDownloadDynamic, state: shellStateUnverified, output: output,
		})
	}
	return downloads
}

func shellDownloadCommand(command string, args []string) bool {
	switch command {
	case "aria2c", shellCommandCurl, "fetch", "wget":
		return true
	case "aws":
		return len(args) > 2 && (strings.EqualFold(args[1], "s3") && strings.EqualFold(args[2], "cp") ||
			strings.EqualFold(args[1], "s3api") && strings.EqualFold(args[2], "get-object"))
	case "gsutil":
		return len(args) > 1 && strings.EqualFold(args[1], "cp")
	default:
		return false
	}
}

func shellDownloadIdentity(argument string) (name, state string, ok bool) {
	if strings.Contains(argument, "$") {
		parsed, err := url.Parse(argument)
		if err == nil && parsed.Scheme != "" && parsed.Host != "" {
			return parsed.Host, shellStateUnverified, true
		}
		return shellDownloadDynamic, shellStateUnverified, true
	}
	parsed, err := url.Parse(argument)
	if err != nil || parsed.Scheme == "" {
		return "", "", false
	}
	switch parsed.Scheme {
	case "http", "https", "ftp", "s3", "gs":
	default:
		return "", "", false
	}
	name = parsed.Host
	if name == "" {
		name = parsed.Scheme
	}
	state = shellStateUnverified
	for _, segment := range strings.Split(strings.Trim(parsed.Path, "/"), "/") {
		if shellHexPathSegment.MatchString(segment) {
			state = "immutable-ref"
			break
		}
	}
	for key, values := range parsed.Query() {
		if strings.Contains(strings.ToLower(key), "sha") {
			for _, value := range values {
				if shellDigestPattern.MatchString(value) {
					state = "digest-addressed"
				}
			}
		}
	}
	return name, state, true
}

func shellDownloadOutput(command string, args []string, statement *syntax.Stmt) string {
	if output := shellRedirectOutput(statement); output != "" {
		return output
	}
	if output := shellOptionOutput(command, args); output != "" {
		return output
	}
	if command == "aws" || command == "gsutil" {
		return args[len(args)-1]
	}
	if command == shellCommandCurl && !shellHasArgument(args, "-O", "--remote-name") {
		return ""
	}
	return shellRemotePath(args)
}

func shellRedirectOutput(statement *syntax.Stmt) string {
	if statement == nil {
		return ""
	}
	for _, redirect := range statement.Redirs {
		if redirect.Op.String() != ">" && redirect.Op.String() != ">>" {
			continue
		}
		if output, ok := shellWordValue(redirect.Word); ok {
			return output
		}
	}
	return ""
}

func shellOptionOutput(command string, args []string) string {
	for index := 1; index < len(args)-1; index++ {
		switch args[index] {
		case "-o", "--output", "--output-document":
			return args[index+1]
		case "-O":
			if command != shellCommandCurl {
				return args[index+1]
			}
		}
	}
	for _, argument := range args[1:] {
		if output, ok := strings.CutPrefix(argument, "--output="); ok {
			return output
		}
		if output, ok := strings.CutPrefix(argument, "--output-document="); ok {
			return output
		}
	}
	return ""
}

func shellHasArgument(args []string, wanted ...string) bool {
	for _, argument := range args[1:] {
		for _, candidate := range wanted {
			if argument == candidate {
				return true
			}
		}
	}
	return false
}

func shellRemotePath(args []string) string {
	for _, argument := range args[1:] {
		parsed, err := url.Parse(argument)
		if err == nil && parsed.Host != "" {
			return path.Base(parsed.Path)
		}
	}
	return ""
}

func mergeShellDownload(downloads map[string]*shellDownload, download *shellDownload) {
	key := strings.Join([]string{download.name, download.output, strconv.FormatUint(uint64(download.line), 10)}, "\x00")
	if existing, ok := downloads[key]; ok {
		if download.executed && (!existing.executed || download.executionOrder < existing.executionOrder) {
			existing.executed = true
			existing.executionOrder = download.executionOrder
		}
		if existing.state == shellStateUnverified {
			existing.state = download.state
		}
		return
	}
	downloads[key] = download
}

func shellChecksumCommand(args []string, line, order uint) (shellChecksum, bool) {
	if len(args) == 0 {
		return shellChecksum{}, false
	}
	command := strings.ToLower(path.Base(args[0]))
	algorithm := command
	if command == "openssl" && len(args) > 2 && strings.EqualFold(args[1], "dgst") {
		algorithm = "openssl-dgst"
	} else if !strings.HasSuffix(command, "sum") && command != "shasum" {
		return shellChecksum{}, false
	}
	check := false
	value := "standard-input"
	for _, argument := range args[1:] {
		if argument == "-c" || argument == "--check" || argument == "-verify" {
			check = true
			continue
		}
		if !strings.HasPrefix(argument, "-") {
			value = argument
		}
	}
	if !check {
		return shellChecksum{}, false
	}
	return shellChecksum{line: line, order: order, algorithm: algorithm, value: value}, true
}

func shellChecksumPipeTarget(args []string) string {
	if len(args) <= 1 || !shellDigestPattern.MatchString(strings.Join(args[1:], " ")) {
		return ""
	}
	match := shellChecksumTarget.FindStringSubmatch(strings.Join(args[1:], " "))
	if len(match) <= 1 {
		return ""
	}
	return match[1]
}

func shellExecutionTarget(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	name := strings.ToLower(path.Base(args[0]))
	if isShellInterpreterName(name) || name == "source" || args[0] == "." {
		for _, argument := range args[1:] {
			if !strings.HasPrefix(argument, "-") {
				return argument, true
			}
		}
	}
	if strings.HasPrefix(args[0], "./") || strings.HasPrefix(args[0], "/tmp/") {
		return args[0], true
	}
	return "", false
}

func shellInterpreterCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return isShellInterpreterName(strings.ToLower(path.Base(args[0])))
}

func isShellInterpreterName(name string) bool {
	return shellLanguageName[name] || shellInterpreterName[name]
}

func sameShellPath(left, right string) bool {
	left = path.Clean(left)
	right = path.Clean(right)
	return left == right || path.Base(left) == path.Base(right)
}
