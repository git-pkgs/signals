package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	githistory "github.com/git-pkgs/history"
	"github.com/git-pkgs/manifests"
	"github.com/git-pkgs/roles"
	"github.com/git-pkgs/spdx"
	"github.com/git-pkgs/vers"
)

const (
	dockerName                  = "docker"
	detectorPackages            = "Packages"
	checkPackageFile            = "Package-File"
	checkDependencyConstraint   = "Dependency-Constraint"
	checkDependencyPin          = "Dependency-Pin"
	checkDependencyPinning      = "Dependency-Pinning"
	checkLockfileIntegrity      = "Lockfile-Integrity"
	checkPackageParse           = "Package-Parse"
	checkPackageProvenance      = "Package-Provenance"
	checkPinnedDependencies     = "Pinned-Dependencies"
	packageProvenanceDisabled   = "disabled"
	packageProvenanceEnabled    = "enabled"
	licenseExpressionInvalid    = "expression-invalid"
	licenseExpressionKind       = "expression"
	licenseExpressionStrict     = "strict"
	licenseExpressionSyntax     = "syntax-only"
	licenseExpressionNormalized = "normalized"
)

var packageChecks = map[string]bool{
	checkPackageFile:          true,
	checkDependencyConstraint: true,
	checkDependencyPin:        true,
	checkDependencyPinning:    true,
	checkLockfileIntegrity:    true,
	checkPackageParse:         true,
	checkPinnedDependencies:   true,
}

type packageCacheKey struct {
	oid  string
	path string
}

func packageSignalsForChanges(
	tree fs.FS,
	changes []githistory.Change,
	cache map[packageCacheKey][]Signal,
) ([]Signal, []string, error) {
	var signals []Signal
	var paths []string
	for _, change := range changes {
		path := change.Path
		if !includePackagePath(path) || len(manifests.IdentifyAll(path)) == 0 {
			continue
		}
		paths = append(paths, path)

		key := packageCacheKey{oid: nonzeroOID(change.NewOID), path: path}
		if key.oid != "" {
			if cached, ok := cache[key]; ok {
				signals = append(signals, cached...)
				continue
			}
		}

		data, err := fs.ReadFile(tree, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read package file %s: %w", path, err)
		}
		parsed := packageFileSignals(path, data)
		signals = append(signals, parsed...)
		if key.oid != "" {
			cache[key] = parsed
		}
	}
	sortSignals(signals)
	return deduplicateSignals(signals), paths, nil
}

func allPackageSignals(tree fs.FS) ([]Signal, error) {
	var signals []Signal
	err := fs.WalkDir(tree, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		if entry.IsDir() {
			if !includePackagePath(path) {
				return fs.SkipDir
			}
			return nil
		}
		if !includePackagePath(path) || len(manifests.IdentifyAll(path)) == 0 {
			return nil
		}

		data, err := fs.ReadFile(tree, path)
		if err != nil {
			return fmt.Errorf("read package file %s: %w", path, err)
		}
		signals = append(signals, packageFileSignals(path, data)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortSignals(signals)
	return deduplicateSignals(signals), nil
}

func packageFileSignals(path string, data []byte) []Signal {
	matches := manifests.IdentifyAll(path)
	var signals []Signal
	for _, match := range matches {
		signals = append(signals, Signal{
			Check: checkPackageFile,
			Kind:  string(match.Kind),
			Name:  match.Ecosystem,
			Path:  path,
		})
	}

	result, err := manifests.Parse(path, data)
	if err != nil {
		for _, match := range matches {
			signals = append(signals, Signal{
				Check: checkPackageParse,
				Kind:  string(match.Kind),
				Name:  match.Ecosystem,
				Value: signalInvalid,
				Path:  path,
			})
		}
		return signals
	}

	signals = append(signals, manifestProvenanceSignals(path, result)...)
	switch result.Kind {
	case manifests.Manifest:
		signals = append(signals, manifestLicenseSignals(path, result)...)
		signals = append(signals, manifestPinSignals(path, result)...)
	case manifests.Lockfile:
		signals = append(signals, lockfileSignals(path, result)...)
	}
	return signals
}

func manifestProvenanceSignals(path string, result *manifests.ParseResult) []Signal {
	provenance := result.Publication.Provenance
	if provenance == nil {
		return nil
	}
	value := packageProvenanceDisabled
	if *provenance {
		value = packageProvenanceEnabled
	}
	return []Signal{{
		Check: checkPackageProvenance,
		Kind:  result.Ecosystem,
		Name:  result.Name,
		Value: value,
		Path:  path,
	}}
}

func manifestLicenseSignals(path string, result *manifests.ParseResult) []Signal {
	signals := make([]Signal, 0, len(result.Licenses)+1)
	for _, license := range result.Licenses {
		license = strings.TrimSpace(license)
		if license == "" {
			continue
		}
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindDeclaration,
			Name:  license,
			Path:  path,
		})
		signals = append(signals, manifestLicenseExpressionSignal(path, license))
	}
	if licenseFile := strings.TrimSpace(result.LicenseFile); licenseFile != "" {
		signals = append(signals, Signal{
			Check: checkLicense,
			Kind:  signalKindFileReference,
			Value: licenseFile,
			Path:  path,
		})
	}
	return signals
}

func manifestLicenseExpressionSignal(path, declaration string) Signal {
	if expression, err := spdx.ParseStrict(declaration); err == nil {
		return Signal{
			Check: checkLicense,
			Kind:  licenseExpressionKind,
			Name:  expression.String(),
			Value: licenseExpressionStrict,
			Path:  path,
		}
	}
	if expression, err := spdx.ParseSyntax(declaration); err == nil {
		return Signal{
			Check: checkLicense,
			Kind:  licenseExpressionKind,
			Name:  expression.String(),
			Value: licenseExpressionSyntax,
			Path:  path,
		}
	}
	if expression, err := spdx.Parse(declaration); err == nil {
		return Signal{
			Check: checkLicense,
			Kind:  licenseExpressionKind,
			Name:  expression.String(),
			Value: licenseExpressionNormalized,
			Path:  path,
		}
	}
	return Signal{
		Check: checkLicense,
		Kind:  licenseExpressionInvalid,
		Name:  declaration,
		Path:  path,
	}
}

func manifestPinSignals(path string, result *manifests.ParseResult) []Signal {
	declarations := result.Declarations
	if len(declarations) == 0 {
		declarations = dependenciesAsDeclarations(result.Dependencies)
	}

	var signals []Signal
	var exact, ranged, unparsed int
	for _, declaration := range declarations {
		if !declaration.Direct {
			continue
		}
		ecosystem := declaration.Ecosystem
		if ecosystem == "" {
			ecosystem = result.Ecosystem
		}
		name := declaration.PURL
		if name == "" {
			name = declaration.Name
		}
		constraint := declaration.Version
		if constraint == "" {
			constraint = "unversioned"
		}

		version, pinned, classified := classifyDependencyPin(declaration.Version, ecosystem)
		switch {
		case !classified:
			unparsed++
		case !pinned:
			ranged++
		default:
			exact++
			signals = append(signals, Signal{
				Check: checkDependencyPin,
				Kind:  ecosystem,
				Name:  name,
				Value: version,
				Path:  path,
			})
		}
		if !classified || !pinned {
			signals = append(signals, Signal{
				Check: checkDependencyConstraint,
				Kind:  ecosystem,
				Name:  name,
				Value: constraint,
				Path:  path,
			})
		}
		if signal, ok := pinnedDependencySignal(path, declaration, pinned, version); ok {
			signals = append(signals, signal)
		}
	}

	if exact+ranged+unparsed > 0 {
		signals = append(signals, Signal{
			Check: checkDependencyPinning,
			Kind:  result.Ecosystem,
			Value: "exact=" + strconv.Itoa(exact) +
				"; ranged=" + strconv.Itoa(ranged) +
				"; unparsed=" + strconv.Itoa(unparsed),
			Path: path,
		})
	}
	return signals
}

func classifyDependencyPin(version, ecosystem string) (string, bool, bool) {
	if version == "" {
		return "", false, false
	}
	switch ecosystem {
	case "github-actions":
		return version, len(version) == 40 && isHex(version), true
	case dockerName:
		digest, ok := strings.CutPrefix(version, "sha256:")
		return version, ok && len(digest) == 64 && isHex(digest), true
	default:
		rng, err := vers.ParseNative(version, ecosystem)
		if err != nil {
			return "", false, false
		}
		exact, pinned := rng.ExactVersion()
		return exact, pinned, true
	}
}

func isHex(value string) bool {
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return value != ""
}

func pinnedDependencySignal(
	path string,
	declaration manifests.Declaration,
	pinned bool,
	version string,
) (Signal, bool) {
	var kind string
	switch declaration.Ecosystem {
	case "github-actions":
		kind = "GitHubAction"
	case dockerName:
		kind = "containerImage"
	default:
		return Signal{}, false
	}
	value := "unpinned"
	if pinned {
		value = "pinned@" + version
	}
	return Signal{
		Check: checkPinnedDependencies,
		Kind:  kind,
		Name:  declaration.Name,
		Value: value,
		Path:  path,
	}, true
}

func dependenciesAsDeclarations(dependencies []manifests.Dependency) []manifests.Declaration {
	declarations := make([]manifests.Declaration, 0, len(dependencies))
	for _, dependency := range dependencies {
		declarations = append(declarations, manifests.Declaration{
			Name:      dependency.Name,
			Version:   dependency.Version,
			Scope:     dependency.Scope,
			Direct:    dependency.Direct,
			PURL:      dependency.PURL,
			Ecosystem: dependency.Ecosystem,
			NoPURL:    dependency.NoPURL,
			Source:    dependency.Source,
		})
	}
	return declarations
}

func lockfileSignals(path string, result *manifests.ParseResult) []Signal {
	resolved := 0
	integrity := 0
	for _, dependency := range result.Dependencies {
		if dependency.Version != "" {
			resolved++
		}
		if dependency.Integrity != "" {
			integrity++
		}
	}

	return []Signal{
		{
			Check: checkDependencyPinning,
			Kind:  result.Ecosystem,
			Value: "resolved=" + strconv.Itoa(resolved) +
				"; total=" + strconv.Itoa(len(result.Dependencies)),
			Path: path,
		},
		{
			Check: checkLockfileIntegrity,
			Kind:  result.Ecosystem,
			Value: "declared=" + strconv.Itoa(integrity) +
				"; total=" + strconv.Itoa(len(result.Dependencies)),
			Path: path,
		},
	}
}

func includePackagePath(path string) bool {
	labels, err := roles.Match(path)
	if err != nil {
		return true
	}
	return !labels.Has(roles.Vendor) && !labels.Has(roles.Fixture) &&
		!labels.Has(roles.Cache) && !labels.Has(roles.BuildOutput)
}

func packagesAffected(changes []githistory.Change) bool {
	for _, change := range changes {
		if includePackagePath(change.Path) && len(manifests.IdentifyAll(change.Path)) > 0 {
			return true
		}
	}
	return false
}

func nonzeroOID(oid string) string {
	if strings.Trim(oid, "0") == "" {
		return ""
	}
	return oid
}

func removePackageSignals(signals map[string]Signal, paths map[string]bool) {
	for key, signal := range signals {
		owned := packageChecks[signal.Check] ||
			signal.Check == checkPackageProvenance && signal.Kind == packagingNameNPM ||
			signal.Check == checkLicense && manifestLicenseSignalKind(signal.Kind)
		if owned && (paths == nil || paths[signal.Path]) {
			delete(signals, key)
		}
	}
}

func manifestLicenseSignalKind(kind string) bool {
	switch kind {
	case signalKindDeclaration, signalKindFileReference, licenseExpressionKind, licenseExpressionInvalid:
		return true
	default:
		return false
	}
}
