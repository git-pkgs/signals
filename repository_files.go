package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	githistory "github.com/git-pkgs/history"
	gitlanguages "github.com/git-pkgs/languages"
	"github.com/git-pkgs/licensecheck"
	"github.com/git-pkgs/magic"
	"github.com/git-pkgs/roles"
	"github.com/git-pkgs/sbom"
)

var (
	securityPolicyURLPattern   = regexp.MustCompile(`(?:https?)://[a-zA-Z0-9./?=_%:#&+~-]*`)
	securityPolicyEmailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+(?:@|\[at\])[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b`)
)

var binaryArtifactExtensions = map[string]bool{
	".a": true, ".bundle": true, ".class": true, ".crx": true, ".deb": true,
	".dex": true, ".dey": true, ".dll": true, ".drv": true, ".dylib": true,
	".efi": true, ".exe": true, ".iso": true, ".jar": true, ".lib": true,
	".msi": true, ".o": true, ".ocx": true, ".par": true, ".pyc": true,
	".pyo": true, ".rpm": true, ".so": true, ".wasm": true, ".whl": true,
}

var sbomFileSuffixes = []string{
	".cdx.json", ".cdx.xml", ".spdx", ".spdx.json", ".spdx.xml",
	".spdx.yml", ".spdx.yaml", ".spdx.rdf", ".spdx.rdf.xml",
}

type fuzzPattern struct {
	name       string
	expression *regexp.Regexp
}

var fuzzPatterns = map[string][]fuzzPattern{
	".c":     {{name: "CLibFuzzer", expression: regexp.MustCompile(`LLVMFuzzerTestOneInput`)}},
	".cc":    {{name: "CppLibFuzzer", expression: regexp.MustCompile(`LLVMFuzzerTestOneInput`)}},
	".cpp":   {{name: "CppLibFuzzer", expression: regexp.MustCompile(`LLVMFuzzerTestOneInput`)}},
	".cs":    {{name: "CSharpPropertyBasedTesting", expression: regexp.MustCompile(`using\s+(?:FsCheck|FsCheck\.(?:NUnit|Xunit)|Expecto\.ExpectoFsCheck)`)}},
	".erl":   {{name: "ErlangPropertyBasedTesting", expression: regexp.MustCompile(`-include_lib\("(?:eqc|proper)/include/(?:eqc|proper)\.hrl"\)\.`)}},
	".ex":    {{name: "ElixirPropertyBasedTesting", expression: regexp.MustCompile(`use\s+(?:PropCheck|ExUnitProperties)`)}},
	".exs":   {{name: "ElixirPropertyBasedTesting", expression: regexp.MustCompile(`use\s+(?:PropCheck|ExUnitProperties)`)}},
	".fs":    {{name: "FSharpPropertyBasedTesting", expression: regexp.MustCompile(`open\s+(?:FsCheck|FsCheck\.(?:NUnit|Xunit)|Expecto\.ExpectoFsCheck)`)}},
	".gleam": {{name: "GleamPropertyBasedTesting", expression: regexp.MustCompile(`import\s+qcheck`)}},
	".go":    {{name: "GoBuiltInFuzzer", expression: regexp.MustCompile(`func\s+Fuzz\w+\s*\(\w+\s+\*testing\.F\)`)}},
	".hrl":   {{name: "ErlangPropertyBasedTesting", expression: regexp.MustCompile(`-include_lib\("(?:eqc|proper)/include/(?:eqc|proper)\.hrl"\)\.`)}},
	".hs":    {{name: "HaskellPropertyBasedTesting", expression: regexp.MustCompile(`import\s+(?:qualified\s+)?Test\.(?:(?:Hspec|Tasty)\.)?(?:QuickCheck|Hedgehog|Validity|SmallCheck)`)}},
	".java":  {{name: "JavaJazzerFuzzer", expression: regexp.MustCompile(`com\.code_intelligence\.jazzer\.api\.FuzzedDataProvider`)}},
	".js":    {{name: "JavaScriptPropertyBasedTesting", expression: regexp.MustCompile(`(?:from\s+['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]|require\(\s*['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]\s*\))`)}},
	".jsx":   {{name: "JavaScriptPropertyBasedTesting", expression: regexp.MustCompile(`(?:from\s+['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]|require\(\s*['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]\s*\))`)}},
	".lhs":   {{name: "HaskellPropertyBasedTesting", expression: regexp.MustCompile(`import\s+(?:qualified\s+)?Test\.(?:(?:Hspec|Tasty)\.)?(?:QuickCheck|Hedgehog|Validity|SmallCheck)`)}},
	".py":    {{name: "PythonAtherisFuzzer", expression: regexp.MustCompile(`(?:from\s+atheris\s+import|import\s+atheris)`)}},
	".rs":    {{name: "RustCargoFuzzer", expression: regexp.MustCompile(`libfuzzer_sys`)}},
	".swift": {{name: "SwiftLibFuzzer", expression: regexp.MustCompile(`LLVMFuzzerTestOneInput`)}},
	".ts":    {{name: "TypeScriptPropertyBasedTesting", expression: regexp.MustCompile(`(?:from\s+['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]|require\(\s*['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]\s*\))`)}},
	".tsx":   {{name: "TypeScriptPropertyBasedTesting", expression: regexp.MustCompile(`(?:from\s+['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]|require\(\s*['"](?:fast-check|@fast-check/(?:ava|jest|vitest))['"]\s*\))`)}},
}

var sonarPOMPattern = regexp.MustCompile(`<sonar\.host\.url>\s*([^<\s]+)\s*</sonar\.host\.url>`)

const (
	repositoryFilePrefixBytes        = 1024
	repositoryFileContentBytes int64 = 1 << 20
	repositoryFileLineBytes          = 1 << 20
	repositoryFileScanBytes          = 64 << 10
	repositoryFileMatchBytes         = 4 << 10
)

type fuzzMatchKey struct {
	pattern int
	offset  int64
}

type repositoryFileCacheKey struct {
	oid  string
	path string
}

func repositoryFileSignalsForChanges(
	tree fs.FS,
	changes []githistory.Change,
	cache map[repositoryFileCacheKey][]Signal,
) ([]Signal, []string, error) {
	var signals []Signal
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		filePath := change.Path
		paths = append(paths, filePath)
		key := repositoryFileCacheKey{oid: nonzeroOID(change.NewOID), path: filePath}
		if key.oid != "" {
			if cached, ok := cache[key]; ok {
				signals = append(signals, cached...)
				continue
			}
		}
		info, err := fs.Stat(tree, filePath)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("stat repository file %s: %w", filePath, err)
		}
		if info.IsDir() {
			continue
		}

		parsed, err := repositoryFileSignalsFromFS(tree, filePath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read repository file %s: %w", filePath, err)
		}
		signals = append(signals, parsed...)
		if key.oid != "" {
			cache[key] = parsed
		}
	}
	sortSignals(signals)
	return deduplicateSignals(signals), paths, nil
}

func allRepositoryFileSignals(tree fs.FS) ([]Signal, error) {
	var signals []Signal
	err := fs.WalkDir(tree, ".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == "." || entry.IsDir() {
			return nil
		}
		parsed, err := repositoryFileSignalsFromFS(tree, filePath)
		if err != nil {
			return fmt.Errorf("read repository file %s: %w", filePath, err)
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

func repositoryFileSignalsFromFS(tree fs.FS, filePath string) ([]Signal, error) {
	prefix, err := readRepositoryFile(tree, filePath, repositoryFilePrefixBytes)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	if signal, ok := binaryArtifactSignal(filePath, prefix, true); ok {
		signals = append(signals, signal)
	}

	license, notice := legalFileKinds(filePath)
	if license {
		data, err := readRepositoryFile(tree, filePath, repositoryFileContentBytes)
		if err != nil {
			return nil, err
		}
		signals = append(signals, licenseSignals(filePath, data)...)
	}
	if notice {
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindNotice,
			Path:  filePath,
		})
	}

	if sbomContentPath(filePath) {
		parsed, err := scanRepositoryFile(tree, filePath, func(reader io.Reader) ([]Signal, error) {
			signal, ok, inspectErr := sbomSignal(filePath, reader)
			if !ok {
				return nil, inspectErr
			}
			return []Signal{signal}, inspectErr
		})
		if err != nil {
			return nil, err
		}
		signals = append(signals, parsed...)
	}

	if securityPolicyPath(filePath) {
		parsed, err := scanRepositoryFile(tree, filePath, func(reader io.Reader) ([]Signal, error) {
			return securityPolicySignals(filePath, reader)
		})
		if err != nil {
			return nil, err
		}
		signals = append(signals, parsed...)
	}

	if fuzzingFile(filePath) {
		parsed, err := scanRepositoryFile(tree, filePath, func(reader io.Reader) ([]Signal, error) {
			return fuzzingSignals(filePath, reader)
		})
		if err != nil {
			return nil, err
		}
		signals = append(signals, parsed...)
	}

	if sastConfigPath(filePath) {
		if strings.EqualFold(path.Base(filePath), "pom.xml") {
			data, err := readRepositoryFile(tree, filePath, repositoryFileContentBytes)
			if err != nil {
				return nil, err
			}
			signals = append(signals, sastConfigSignals(filePath, data)...)
		} else {
			signals = append(signals, sastConfigSignals(filePath, nil)...)
		}
	}
	return signals, nil
}

func readRepositoryFile(tree fs.FS, filePath string, limit int64) ([]byte, error) {
	var data []byte
	err := scanRepositoryFileError(tree, filePath, func(reader io.Reader) error {
		var err error
		data, err = io.ReadAll(io.LimitReader(reader, limit))
		return err
	})
	return data, err
}

func scanRepositoryFile(
	tree fs.FS,
	filePath string,
	scan func(io.Reader) ([]Signal, error),
) ([]Signal, error) {
	var signals []Signal
	err := scanRepositoryFileError(tree, filePath, func(reader io.Reader) error {
		var err error
		signals, err = scan(reader)
		return err
	})
	return signals, err
}

func scanRepositoryFileError(tree fs.FS, filePath string, scan func(io.Reader) error) error {
	file, err := tree.Open(filePath)
	if err != nil {
		return err
	}
	return errors.Join(scan(file), file.Close())
}

func sbomContentPath(filePath string) bool {
	if sbomFileName(filePath) {
		return true
	}
	switch strings.ToLower(path.Ext(filePath)) {
	case ".json", ".xml", ".yaml", ".yml", ".rdf":
		return true
	default:
		return false
	}
}

func sastConfigPath(filePath string) bool {
	switch strings.ToLower(path.Base(filePath)) {
	case "pom.xml", "sonar-project.properties", "qodana.yaml", "qodana.yml":
		return true
	default:
		return false
	}
}

func binaryArtifactSignal(filePath string, data []byte, prefix bool) (Signal, bool) {
	result := magic.Detect(data)
	if prefix {
		result = magic.DetectPrefix(data)
	}
	if result.Kind != magic.KindBinary {
		return Signal{}, false
	}
	extension := strings.ToLower(path.Ext(filePath))
	compiledFormat := result.Format == magic.FormatELF || result.Format == magic.FormatMachO ||
		result.Format == magic.FormatJavaClass || result.Format == magic.FormatPE ||
		result.Format == magic.FormatWASM || result.Format == magic.FormatAR
	if !compiledFormat && !binaryArtifactExtensions[extension] {
		return Signal{}, false
	}
	return Signal{
		Check: checkBinaryArtifacts,
		Kind:  "artifact",
		Name:  result.Format,
		Value: result.MIME,
		Path:  filePath,
	}, true
}

func legalFileKinds(filePath string) (license, notice bool) {
	classification, err := roles.Classify(filePath)
	labels := classification.Set()
	if err != nil || labels.BundledOrDerived() || !legalDocumentPath(filePath) {
		return false, false
	}
	for _, evidence := range classification.Evidence {
		if evidence.Role != roles.Legal {
			continue
		}
		license = license || evidence.Subtype == signalKindLicense
		notice = notice || evidence.Subtype == signalKindNotice
	}
	return license, notice
}

func legalDocumentPath(filePath string) bool {
	language := gitlanguages.AnalyzePath(filePath).Result().Language
	switch language {
	case gitlanguages.Unknown,
		gitlanguages.AsciiDoc,
		gitlanguages.Creole,
		gitlanguages.HTML,
		gitlanguages.Markdown,
		gitlanguages.Org,
		gitlanguages.Pod,
		gitlanguages.ReStructuredText,
		gitlanguages.Roff,
		gitlanguages.RoffManpage,
		gitlanguages.TeX,
		gitlanguages.Text,
		gitlanguages.Textile,
		gitlanguages.XML:
		return true
	default:
		return false
	}
}

func licenseSignals(filePath string, data []byte) []Signal {
	coverage := licensecheck.Scan(data)
	seen := make(map[string]bool)
	var signals []Signal
	for _, match := range coverage.Match {
		if match.ID == "" || seen[match.ID] {
			continue
		}
		seen[match.ID] = true
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindLicense,
			Name:  match.ID,
			Path:  filePath,
		})
	}
	if len(signals) == 0 {
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindLicense,
			Name:  "NOASSERTION",
			Path:  filePath,
		})
	}
	return signals
}

func sbomSignal(filePath string, reader io.Reader) (Signal, bool, error) {
	metadata, err := sbom.Inspect(reader)
	if errors.Is(err, sbom.ErrUnrecognized) {
		if !sbomFileName(filePath) {
			return Signal{}, false, nil
		}
		return Signal{
			Check: checkSBOM,
			Kind:  "candidate",
			Name:  path.Base(filePath),
			Path:  filePath,
			Line:  1,
		}, true, nil
	}
	if err != nil {
		return Signal{}, false, err
	}
	return Signal{
		Check: checkSBOM,
		Kind:  "document",
		Name:  string(metadata.Type),
		Value: metadata.SpecVersion,
		Path:  filePath,
		Line:  1,
	}, true, nil
}

func sbomFileName(filePath string) bool {
	lower := strings.ToLower(path.Base(filePath))
	if lower == "bom.json" || lower == "bom.xml" {
		return true
	}
	for _, suffix := range sbomFileSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func securityPolicyPath(filePath string) bool {
	switch strings.ToLower(filePath) {
	case "security.md", ".github/security.md", "docs/security.md",
		"security.markdown", ".github/security.markdown", "docs/security.markdown",
		"security.adoc", ".github/security.adoc", "docs/security.adoc",
		"security.rst", ".github/security.rst", "doc/security.rst", "docs/security.rst":
		return true
	default:
		return false
	}
}

func securityPolicySignals(filePath string, reader io.Reader) ([]Signal, error) {
	signals := []Signal{{
		Check: checkSecurityPolicy,
		Kind:  "policy",
		Path:  filePath,
		Line:  1,
	}}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(nil, repositoryFileLineBytes)
	line := uint(0)
	for scanner.Scan() {
		line++
		text := scanner.Text()
		for _, value := range securityPolicyURLs(text) {
			signals = append(signals, Signal{
				Check: checkSecurityPolicy,
				Kind:  "link",
				Value: value,
				Path:  filePath,
				Line:  line,
			})
		}
		for _, value := range securityPolicyEmailPattern.FindAllString(text, -1) {
			signals = append(signals, Signal{
				Check: checkSecurityPolicy,
				Kind:  "email",
				Value: value,
				Path:  filePath,
				Line:  line,
			})
		}
	}
	return signals, scanner.Err()
}

func securityPolicyURLs(text string) []string {
	matches := securityPolicyURLPattern.FindAllStringIndex(text, -1)
	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		value := text[match[0]:match[1]]
		if !explicitMarkdownURL(text, match[0], match[1]) {
			value = strings.TrimRight(value, ".")
		}
		urls = append(urls, value)
	}
	return urls
}

func explicitMarkdownURL(text string, start, end int) bool {
	markdownDestination := start >= 2 && text[start-1] == '(' && text[start-2] == ']' &&
		end < len(text) && text[end] == ')'
	autolink := start > 0 && text[start-1] == '<' && end < len(text) && text[end] == '>'
	return markdownDestination || autolink
}

func fuzzingFile(filePath string) bool {
	if filePath == ".clusterfuzzlite/Dockerfile" {
		return true
	}
	labels, err := roles.Match(filePath)
	if err == nil && labels.BundledOrDerived() {
		return false
	}
	return len(fuzzPatterns[strings.ToLower(path.Ext(filePath))]) > 0
}

func fuzzingSignals(filePath string, reader io.Reader) ([]Signal, error) {
	if filePath == ".clusterfuzzlite/Dockerfile" {
		return clusterFuzzLiteSignals(filePath, reader)
	}
	patterns := fuzzPatterns[strings.ToLower(path.Ext(filePath))]
	buffer := make([]byte, repositoryFileScanBytes)
	seen := make(map[fuzzMatchKey]bool)
	var signals []Signal
	var carry []byte
	windowOffset := int64(0)
	windowLine := uint(1)
	for {
		n, err := io.ReadFull(reader, buffer)
		if n > 0 {
			window := make([]byte, len(carry)+n)
			copy(window, carry)
			copy(window[len(carry):], buffer[:n])
			signals = append(signals, fuzzingSignalsInWindow(
				filePath, patterns, window, windowOffset, windowLine, seen,
			)...)

			keep := min(len(window), repositoryFileMatchBytes)
			trim := len(window) - keep
			windowOffset += int64(trim)
			windowLine += uint(bytes.Count(window[:trim], []byte{'\n'}))
			carry = append(carry[:0], window[trim:]...)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return signals, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func clusterFuzzLiteSignals(filePath string, reader io.Reader) ([]Signal, error) {
	buffer := make([]byte, repositoryFileScanBytes)
	for {
		n, err := reader.Read(buffer)
		if len(bytes.TrimSpace(buffer[:n])) > 0 {
			return []Signal{{
				Check: checkFuzzing,
				Kind:  "fuzzer",
				Name:  "ClusterFuzzLite",
				Path:  filePath,
				Line:  1,
			}}, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, err
		}
	}
}

func fuzzingSignalsInWindow(
	filePath string,
	patterns []fuzzPattern,
	data []byte,
	offset int64,
	line uint,
	seen map[fuzzMatchKey]bool,
) []Signal {
	var signals []Signal
	for patternIndex, pattern := range patterns {
		for _, match := range pattern.expression.FindAllIndex(data, -1) {
			key := fuzzMatchKey{pattern: patternIndex, offset: offset + int64(match[0])}
			if seen[key] {
				continue
			}
			seen[key] = true
			signals = append(signals, Signal{
				Check: checkFuzzing,
				Kind:  "fuzzer",
				Name:  pattern.name,
				Value: string(data[match[0]:match[1]]),
				Path:  filePath,
				Line:  line + uint(bytes.Count(data[:match[0]], []byte{'\n'})),
			})
		}
	}
	return signals
}

func sastConfigSignals(filePath string, data []byte) []Signal {
	base := strings.ToLower(path.Base(filePath))
	switch base {
	case "sonar-project.properties":
		return []Signal{{Check: checkSAST, Kind: signalKindTool, Name: sastToolSonar, Path: filePath, Line: 1}}
	case "qodana.yaml", "qodana.yml":
		return []Signal{{Check: checkSAST, Kind: signalKindTool, Name: "Qodana", Path: filePath, Line: 1}}
	case "pom.xml":
		match := sonarPOMPattern.FindSubmatchIndex(data)
		if len(match) == 0 {
			return nil
		}
		return []Signal{{
			Check: checkSAST,
			Kind:  signalKindTool,
			Name:  sastToolSonar,
			Value: string(data[match[2]:match[3]]),
			Path:  filePath,
			Line:  lineForOffset(data, match[0]),
		}}
	default:
		return nil
	}
}

func lineForOffset(data []byte, offset int) uint {
	return uint(bytes.Count(data[:offset], []byte{'\n'}) + 1)
}

func (d *localDetectors) runRepositoryFiles(
	tree fs.FS,
	changes []githistory.Change,
	run, forceFull bool,
	current *commitState,
	stats *scanStats,
) {
	detectorStats := stats.detectors[detectorRepositoryFiles]
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
		signals, err = allRepositoryFileSignals(tree)
	} else {
		signals, paths, err = repositoryFileSignalsForChanges(tree, changes, d.repositoryFileCache)
	}
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorRepositoryFiles] = err.Error()
		return
	}

	delete(current.errors, detectorRepositoryFiles)
	checks := []string{checkBinaryArtifacts, checkFuzzing, checkLicense, checkSAST, checkSBOM, checkSecurityPolicy}
	if forceFull {
		for _, check := range checks {
			switch check {
			case checkLicense:
				removeRepositoryLicenseSignals(current.signals, nil)
			case checkSAST:
				removeRepositorySASTSignals(current.signals)
			default:
				removeCheckSignals(current.signals, check)
			}
		}
	} else {
		pathSet := make(map[string]bool, len(paths))
		sastPathSet := make(map[string]bool, len(paths))
		for _, filePath := range paths {
			pathSet[filePath] = true
			if !isWorkflowPath(filePath) {
				sastPathSet[filePath] = true
			}
		}
		for _, check := range checks {
			switch check {
			case checkLicense:
				removeRepositoryLicenseSignals(current.signals, pathSet)
			case checkSAST:
				removePathSignals(current.signals, check, sastPathSet)
			default:
				removePathSignals(current.signals, check, pathSet)
			}
		}
	}
	addSignals(current.signals, signals)
}

func removeRepositoryLicenseSignals(signals map[string]Signal, paths map[string]bool) {
	for key, signal := range signals {
		owned := signal.Check == checkLicense &&
			(signal.Kind == signalKindLicense || signal.Kind == signalKindNotice)
		if owned && (paths == nil || paths[signal.Path]) {
			delete(signals, key)
		}
	}
}

func removeRepositorySASTSignals(signals map[string]Signal) {
	for key, signal := range signals {
		if signal.Check == checkSAST && !isWorkflowPath(signal.Path) {
			delete(signals, key)
		}
	}
}
