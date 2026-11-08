package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	gitcerts "github.com/git-pkgs/certs"
	"github.com/git-pkgs/cwe"
	githistory "github.com/git-pkgs/history"
	gitlanguages "github.com/git-pkgs/languages"
	gitlicenses "github.com/git-pkgs/licenses"
	"github.com/git-pkgs/magic"
	"github.com/git-pkgs/roles"
	sarifsummary "github.com/git-pkgs/sarif/summary"
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
	repositoryFilePrefixBytes         = 1024
	repositoryFileContentBytes  int64 = 1 << 20
	repositoryFileLineBytes           = 1 << 20
	repositoryFileScanBytes           = 64 << 10
	repositoryFileMatchBytes          = 4 << 10
	certificateMaxInputBytes          = 8 << 20
	certificateMaxExpandedBytes       = 32 << 20
	certificateMaxEntries             = 10_000
	certificateMaxDepth               = 3
	certificateMaxOccurrences         = 5_000
	certificateMaxDiagnostics         = 100
	certificateCoverageKind           = "coverage"
	asn1SequenceTag                   = 0x30
	asn1LongLengthFlag                = 0x80
	asn1LengthMask                    = 0x7f
	asn1HeaderBytes                   = 2
	asn1MaxLengthBytes                = 4
	bitsPerByte                       = 8
	sarifMaxBytes                     = 16 << 20
	sarifMaxUniqueValues              = 5_000
	sarifMaxTools                     = 100
)

var certificateFileExtensions = map[string]bool{
	".cer": true, ".crt": true, ".der": true, ".jks": true,
	".keystore": true, ".p12": true, ".pem": true, ".pfx": true,
	".truststore": true,
}

type fuzzMatchKey struct {
	pattern int
	offset  int64
}

type repositoryFileCacheKey struct {
	oid  string
	path string
}

func repositoryFileSignalsForChanges(
	ctx context.Context,
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

		parsed, err := repositoryFileSignalsFromFS(ctx, tree, filePath, info.Size())
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

func allRepositoryFileSignals(ctx context.Context, tree fs.FS) ([]Signal, error) {
	var signals []Signal
	err := fs.WalkDir(tree, ".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == "." || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		parsed, err := repositoryFileSignalsFromFS(ctx, tree, filePath, info.Size())
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

func repositoryFileSignalsFromFS(
	ctx context.Context,
	tree fs.FS,
	filePath string,
	size int64,
) ([]Signal, error) {
	prefix, err := readRepositoryFile(tree, filePath, repositoryFilePrefixBytes)
	if err != nil {
		return nil, err
	}
	var signals []Signal
	if signal, ok := binaryArtifactSignal(filePath, prefix, true); ok {
		signals = append(signals, signal)
	}

	certificates, err := repositoryCertificateSignals(ctx, tree, filePath, prefix, size)
	if err != nil {
		return nil, err
	}
	signals = append(signals, certificates...)

	license, notice := legalFileKinds(filePath)
	if license || notice {
		data, err := readRepositoryFile(tree, filePath, repositoryFileContentBytes)
		if err != nil {
			return nil, err
		}
		matched, err := licenseSignals(ctx, filePath, data, license)
		if err != nil {
			return nil, err
		}
		signals = append(signals, matched...)
	}
	if notice {
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindNotice,
			Path:  filePath,
		})
	}

	structured, err := repositoryStructuredSignals(tree, filePath)
	if err != nil {
		return nil, err
	}
	signals = append(signals, structured...)

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

func repositoryStructuredSignals(tree fs.FS, filePath string) ([]Signal, error) {
	if sarifFilePath(filePath) {
		return scanRepositoryFile(tree, filePath, func(reader io.Reader) ([]Signal, error) {
			return sarifSignals(filePath, reader)
		})
	}
	if !sbomContentPath(filePath) {
		return nil, nil
	}
	return scanRepositoryFile(tree, filePath, func(reader io.Reader) ([]Signal, error) {
		signal, ok, err := sbomSignal(filePath, reader)
		if !ok {
			return nil, err
		}
		return []Signal{signal}, err
	})
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

func certificateFileCandidate(filePath string, prefix []byte, size int64) bool {
	labels, err := roles.Match(filePath)
	if err == nil && (labels.Has(roles.Test) || labels.Has(roles.Fixture) || labels.Has(roles.Example) ||
		labels.Has(roles.Cache) || labels.Has(roles.BuildOutput)) {
		return false
	}
	if certificateFileExtensions[strings.ToLower(path.Ext(filePath))] {
		return true
	}
	base := strings.ToLower(path.Base(filePath))
	if base == "cacerts" || base == "ca-bundle" || base == "truststore" {
		return true
	}
	if bytes.Contains(prefix, []byte("-----BEGIN CERTIFICATE-----")) {
		return true
	}
	if len(prefix) >= 4 && bytes.Equal(prefix[:4], []byte{0xfe, 0xed, 0xfe, 0xed}) {
		return true
	}
	if asn1Size := certificateASN1Size(prefix); asn1Size > 0 && asn1Size == size {
		return true
	}
	switch magic.DetectPrefix(prefix).Format {
	case magic.FormatZIP, magic.FormatTAR, magic.FormatGZIP, magic.FormatBZIP2, magic.FormatXZ, magic.FormatZstd:
		return true
	default:
		return false
	}
}

func repositoryCertificateSignals(
	ctx context.Context,
	tree fs.FS,
	filePath string,
	prefix []byte,
	size int64,
) ([]Signal, error) {
	if !certificateFileCandidate(filePath, prefix, size) {
		return nil, nil
	}
	if size > certificateMaxInputBytes {
		return []Signal{{
			Check: checkCertificate,
			Kind:  certificateCoverageKind,
			Name:  "oversized",
			Value: "bytes=" + strconv.FormatInt(size, 10) +
				"; limit=" + strconv.FormatInt(certificateMaxInputBytes, 10),
			Path: filePath,
		}}, nil
	}
	return scanRepositoryFile(tree, filePath, func(reader io.Reader) ([]Signal, error) {
		return certificateSignals(ctx, filePath, reader)
	})
}

func certificateASN1Size(prefix []byte) int64 {
	if len(prefix) < asn1HeaderBytes || prefix[0] != asn1SequenceTag {
		return 0
	}
	length := int64(prefix[1])
	header := int64(asn1HeaderBytes)
	if prefix[1]&asn1LongLengthFlag != 0 {
		bytes := int(prefix[1] & asn1LengthMask)
		if bytes == 0 || bytes > asn1MaxLengthBytes || len(prefix) < asn1HeaderBytes+bytes {
			return 0
		}
		length = 0
		for _, value := range prefix[asn1HeaderBytes : asn1HeaderBytes+bytes] {
			length = length<<bitsPerByte | int64(value)
		}
		header += int64(bytes)
	}
	return header + length
}

func certificateSignals(ctx context.Context, filePath string, reader io.Reader) ([]Signal, error) {
	inventory, err := gitcerts.Scan(ctx, filePath, reader, gitcerts.Options{
		MaxInputBytes:    certificateMaxInputBytes,
		MaxFileBytes:     certificateMaxInputBytes,
		MaxExpandedBytes: certificateMaxExpandedBytes,
		MaxEntries:       certificateMaxEntries,
		MaxDepth:         certificateMaxDepth,
		MaxCertificates:  certificateMaxOccurrences,
		MaxDiagnostics:   certificateMaxDiagnostics,
	})
	if err != nil {
		return nil, err
	}
	var signals []Signal
	for _, certificate := range inventory.Certificates {
		signals = append(signals, Signal{
			Check: checkCertificate,
			Kind:  "identity",
			Name:  certificate.SHA256,
			Value: certificateValue(certificate),
			Path:  filePath,
		})
	}
	for _, collection := range inventory.Collections {
		location := certificateLocation(collection.Location)
		if collection.SetSHA256 != "" {
			signals = append(signals, Signal{
				Check: checkCertificate,
				Kind:  "collection",
				Name:  collection.SetSHA256,
				Value: "format=" + collection.Format +
					"; certificates=" + strconv.Itoa(len(collection.Occurrences)) +
					"; location=" + location,
				Path: filePath,
			})
		}
		for _, match := range collection.Matches {
			signals = append(signals, Signal{
				Check: checkCertificate,
				Kind:  "reference-match",
				Name:  match.Name,
				Value: "kind=" + match.Kind +
					"; shared=" + strconv.Itoa(match.Shared) +
					"; missing=" + strconv.Itoa(len(match.Missing)) +
					"; additional=" + strconv.Itoa(len(match.Additional)) +
					"; location=" + location +
					"; source=" + match.Source,
				Path: filePath,
			})
		}
	}
	if !inventory.Complete {
		signals = append(signals, certificateCoverageSignal(filePath, inventory.Diagnostics))
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func certificateCoverageSignal(filePath string, diagnostics []gitcerts.Diagnostic) Signal {
	counts := make(map[string]int)
	for _, diagnostic := range diagnostics {
		code := diagnostic.Code
		if code == "" {
			code = "unknown"
		}
		counts[code]++
	}
	codes := make([]string, 0, len(counts))
	for code := range counts {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		parts = append(parts, code+"="+strconv.Itoa(counts[code]))
	}
	return Signal{
		Check: checkCertificate,
		Kind:  certificateCoverageKind,
		Name:  "incomplete",
		Value: strings.Join(parts, "; "),
		Path:  filePath,
	}
}

func certificateValue(certificate gitcerts.Certificate) string {
	return "spki=" + certificate.SPKISHA256 +
		"; subject=" + certificateName(certificate.Subject) +
		"; issuer=" + certificateName(certificate.Issuer) +
		"; not-before=" + certificate.NotBefore.UTC().Format(time.RFC3339) +
		"; not-after=" + certificate.NotAfter.UTC().Format(time.RFC3339) +
		"; ca=" + strconv.FormatBool(certificate.IsCA)
}

func certificateName(value string) string {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return strconv.Quote(value)
	}
	return value
}

func certificateLocation(location []gitcerts.Member) string {
	parts := make([]string, 0, len(location))
	for _, member := range location {
		part := member.Path
		if member.Entry > 0 {
			part += "#" + strconv.Itoa(member.Entry)
		}
		parts = append(parts, part)
	}
	return certificateName(strings.Join(parts, "!"))
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

func licenseSignals(
	ctx context.Context,
	filePath string,
	data []byte,
	reportNoAssertion bool,
) ([]Signal, error) {
	matcher, err := repositoryLicenseMatcher()
	if err != nil {
		return nil, fmt.Errorf("load license matcher: %w", err)
	}
	result, err := matcher.Match(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("match license file %s: %w", filePath, err)
	}
	var signals []Signal
	for _, detection := range result.Detections {
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindLicense,
			Name:  detection.Expression,
			Path:  filePath,
		})
	}
	if len(signals) == 0 && reportNoAssertion {
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindLicense,
			Name:  "NOASSERTION",
			Path:  filePath,
			Line:  1,
		})
	}
	return signals, nil
}

var repositoryLicenseMatcher = sync.OnceValues(func() (*gitlicenses.Matcher, error) {
	return gitlicenses.New()
})

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

func sarifFilePath(filePath string) bool {
	labels, err := roles.Match(filePath)
	if err == nil && (labels.BundledOrDerived() || labels.Has(roles.Test) || labels.Has(roles.Example)) {
		return false
	}
	lower := strings.ToLower(path.Base(filePath))
	return strings.HasSuffix(lower, ".sarif") || strings.HasSuffix(lower, ".sarif.json")
}

func sarifSignals(filePath string, reader io.Reader) ([]Signal, error) {
	inspection, err := sarifsummary.Inspect(reader, sarifsummary.Options{
		MaxBytes:        sarifMaxBytes,
		MaxUniqueValues: sarifMaxUniqueValues,
		MaxTools:        sarifMaxTools,
	})
	if errors.Is(err, sarifsummary.ErrInvalid) {
		return []Signal{{
			Check: checkSARIF,
			Kind:  "candidate",
			Name:  "invalid",
			Path:  filePath,
		}}, nil
	}
	if err != nil && !errors.Is(err, sarifsummary.ErrLimit) {
		return nil, err
	}

	signals := []Signal{{
		Check: checkSARIF,
		Kind:  "document",
		Name:  inspection.Version,
		Value: "runs=" + strconv.Itoa(inspection.Runs) +
			"; results=" + strconv.Itoa(inspection.Results) +
			"; occurrences=" + strconv.Itoa(inspection.Occurrences) +
			"; suppressed=" + strconv.Itoa(inspection.SuppressedResults),
		Path: filePath,
	}}
	for _, tool := range inspection.Tools {
		value := ""
		if tool.SemanticVersion != "" {
			value = "semantic-version=" + tool.SemanticVersion
		}
		if tool.Version != "" {
			if value != "" {
				value += "; "
			}
			value += "version=" + tool.Version
		}
		signals = append(signals, Signal{
			Check: checkSARIF,
			Kind:  "tool",
			Name:  tool.Name,
			Value: value,
			Path:  filePath,
		})
	}
	signals = appendSARIFCounts(signals, filePath, "level", inspection.Levels)
	signals = appendSARIFCounts(signals, filePath, "baseline", inspection.BaselineStates)
	signals = appendSARIFCounts(signals, filePath, "rule", inspection.Rules)
	signals = appendSARIFTaxa(signals, filePath, inspection.Taxa)
	signals = appendSARIFCWE(signals, filePath, inspection.Taxa)
	signals = appendSARIFCounts(signals, filePath, "suppression", inspection.Suppressions)
	if inspection.Truncated || errors.Is(err, sarifsummary.ErrLimit) {
		signals = append(signals, Signal{
			Check: checkSARIF,
			Kind:  "coverage",
			Name:  "truncated",
			Path:  filePath,
		})
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func appendSARIFTaxa(signals []Signal, filePath string, taxa []sarifsummary.Taxon) []Signal {
	for _, taxon := range taxa {
		name := taxon.ID
		if name == "" {
			name = taxon.GUID
		}
		switch {
		case isCWETaxonomy(taxon.TaxonomyName):
			if id, _, ok := cwe.Lookup(name); ok {
				name = id
			} else {
				name = "CWE:" + name
			}
		case taxon.TaxonomyName != "":
			name = taxon.TaxonomyName + ":" + name
		case taxon.TaxonomyGUID != "":
			name = taxon.TaxonomyGUID + ":" + name
		}
		signals = append(signals, Signal{
			Check: checkSARIF,
			Kind:  "taxon",
			Name:  name,
			Value: strconv.Itoa(taxon.Count),
			Path:  filePath,
		})
	}
	return signals
}

func appendSARIFCWE(signals []Signal, filePath string, taxa []sarifsummary.Taxon) []Signal {
	type weakness struct {
		count      int
		name       string
		categoryID string
	}
	weaknesses := make(map[string]weakness)
	categories := make(map[string]int)
	categoryNames := make(map[string]string)
	for _, taxon := range taxa {
		if !isCWETaxonomy(taxon.TaxonomyName) {
			continue
		}
		id, entry, ok := cwe.Lookup(taxon.ID)
		if !ok {
			continue
		}
		categoryID := cwe.CategoryID(entry.Category)
		current := weaknesses[id]
		current.count += taxon.Count
		current.name = entry.Name
		current.categoryID = categoryID
		weaknesses[id] = current
		if categoryID != "" {
			categories[categoryID] += taxon.Count
			categoryNames[categoryID] = entry.Category
		}
	}

	ids := make([]string, 0, len(weaknesses))
	for id := range weaknesses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		item := weaknesses[id]
		value := "count=" + strconv.Itoa(item.count) + "; name=" + item.name
		if item.categoryID != "" {
			value += "; category=" + item.categoryID
		}
		signals = append(signals, Signal{
			Check: checkSARIF,
			Kind:  "weakness",
			Name:  id,
			Value: value,
			Path:  filePath,
		})
	}
	ids = ids[:0]
	for id := range categories {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		signals = append(signals, Signal{
			Check: checkSARIF,
			Kind:  "weakness-category",
			Name:  id,
			Value: "count=" + strconv.Itoa(categories[id]) + "; name=" + categoryNames[id],
			Path:  filePath,
		})
	}
	return signals
}

func isCWETaxonomy(name string) bool {
	return strings.EqualFold(name, "CWE") || strings.EqualFold(name, "Common Weakness Enumeration")
}

func appendSARIFCounts(signals []Signal, filePath, kind string, counts map[string]int) []Signal {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		signals = append(signals, Signal{
			Check: checkSARIF,
			Kind:  kind,
			Name:  name,
			Value: strconv.Itoa(counts[name]),
			Path:  filePath,
		})
	}
	return signals
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
	ctx context.Context,
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
		signals, err = allRepositoryFileSignals(ctx, tree)
	} else {
		signals, paths, err = repositoryFileSignalsForChanges(
			ctx,
			tree,
			changes,
			d.repositoryFileCache,
		)
	}
	detectorStats.duration += time.Since(started)
	if err != nil {
		current.errors[detectorRepositoryFiles] = err.Error()
		return
	}

	delete(current.errors, detectorRepositoryFiles)
	checks := []string{checkBinaryArtifacts, checkCertificate, checkFuzzing, checkLicense, checkSARIF, checkSAST, checkSBOM, checkSecurityPolicy}
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
