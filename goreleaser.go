package main

import (
	"path"
	"slices"
	"strings"

	"github.com/git-pkgs/roles"
	"go.yaml.in/yaml/v3"
)

const (
	goreleaserKindSign        = "artifact"
	goreleaserKindDockerSign  = "container"
	goreleaserKindBinarySign  = "binary"
	goreleaserKindPackageSign = "package"
	goreleaserKindSBOM        = "GoReleaser"
	goreleaserGPGCommand      = "gpg"
	goreleaserNFPMCommand     = "nfpm"
	goreleaserArtifactsNone   = "none"
)

type goreleaserConfig struct {
	Signs       []goreleaserSign `yaml:"signs"`
	DockerSigns []goreleaserSign `yaml:"docker_signs"`
	BinarySigns []goreleaserSign `yaml:"binary_signs"`
	SBOMs       []goreleaserSBOM `yaml:"sboms"`
	NFPMs       []goreleaserNFPM `yaml:"nfpms"`
	SRPM        goreleaserSRPM   `yaml:"srpm"`
}

type goreleaserSign struct {
	Cmd       string   `yaml:"cmd"`
	Artifacts string   `yaml:"artifacts"`
	IDs       []string `yaml:"ids"`
}

type goreleaserSBOM struct {
	Cmd       string    `yaml:"cmd"`
	Artifacts string    `yaml:"artifacts"`
	IDs       []string  `yaml:"ids"`
	Disable   yaml.Node `yaml:"disable"`
}

type goreleaserNFPM struct {
	ID        string                            `yaml:"id"`
	IDs       []string                          `yaml:"ids"`
	Builds    []string                          `yaml:"builds"`
	Formats   []string                          `yaml:"formats"`
	RPM       goreleaserPackage                 `yaml:"rpm"`
	Deb       goreleaserPackage                 `yaml:"deb"`
	APK       goreleaserPackage                 `yaml:"apk"`
	MSIX      goreleaserPackage                 `yaml:"msix"`
	Overrides map[string]goreleaserNFPMSettings `yaml:"overrides"`
}

type goreleaserNFPMSettings struct {
	RPM  goreleaserPackage `yaml:"rpm"`
	Deb  goreleaserPackage `yaml:"deb"`
	APK  goreleaserPackage `yaml:"apk"`
	MSIX goreleaserPackage `yaml:"msix"`
}

type goreleaserPackage struct {
	Signature goreleaserPackageSignature `yaml:"signature"`
}

type goreleaserPackageSignature struct {
	KeyFile string `yaml:"key_file"`
	PFXFile string `yaml:"pfx_file"`
}

type goreleaserSRPM struct {
	Enabled   bool                       `yaml:"enabled"`
	Signature goreleaserPackageSignature `yaml:"signature"`
}

func goreleaserConfigPath(filePath string) bool {
	labels, err := roles.Match(filePath)
	if err == nil && labels.BundledOrDerived() {
		return false
	}
	switch strings.ToLower(path.Base(filePath)) {
	case ".goreleaser.yml", ".goreleaser.yaml", "goreleaser.yml", "goreleaser.yaml":
		return true
	default:
		return false
	}
}

func goreleaserSignals(filePath string, data []byte) []Signal {
	var config goreleaserConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil
	}

	var signals []Signal
	signals = append(signals, goreleaserSignSignals(filePath, goreleaserKindSign, config.Signs, goreleaserGPGCommand, goreleaserArtifactsNone)...)
	signals = append(signals, goreleaserSignSignals(filePath, goreleaserKindDockerSign, config.DockerSigns, "cosign", "docker-v2")...)
	signals = append(signals, goreleaserSignSignals(filePath, goreleaserKindBinarySign, config.BinarySigns, goreleaserGPGCommand, "binary")...)
	signals = append(signals, goreleaserPackageSignSignals(filePath, config.NFPMs, config.SRPM)...)
	for _, sbom := range config.SBOMs {
		if goreleaserDisabled(sbom.Disable) {
			continue
		}
		command := sbom.Cmd
		if command == "" {
			command = "syft"
		}
		artifacts := sbom.Artifacts
		if artifacts == "" {
			artifacts = "archive"
		}
		if artifacts == goreleaserArtifactsNone {
			continue
		}
		signals = append(signals, Signal{
			Check: checkSBOMGeneration,
			Kind:  goreleaserKindSBOM,
			Name:  command,
			Value: goreleaserSelection(artifacts, effectiveSBOMIDs(artifacts, sbom.IDs)),
			Path:  filePath,
		})
	}
	return signals
}

func goreleaserSignSignals(
	filePath, kind string,
	configs []goreleaserSign,
	defaultCommand, defaultArtifacts string,
) []Signal {
	var signals []Signal
	for _, config := range configs {
		artifacts := config.Artifacts
		if artifacts == "" {
			artifacts = defaultArtifacts
		}
		if artifacts == goreleaserArtifactsNone {
			continue
		}
		command := config.Cmd
		if command == "" {
			command = defaultCommand
		}
		signals = append(signals, Signal{
			Check: checkArtifactSigning,
			Kind:  kind,
			Name:  command,
			Value: goreleaserSelection(artifacts, effectiveSignIDs(kind, artifacts, config.IDs)),
			Path:  filePath,
		})
	}
	return signals
}

func goreleaserPackageSignSignals(filePath string, configs []goreleaserNFPM, srpm goreleaserSRPM) []Signal {
	var signals []Signal
	for _, config := range configs {
		id := config.ID
		if id == "" {
			id = "default"
		}
		selectors := append(slices.Clone(config.IDs), config.Builds...)
		for _, format := range config.Formats {
			format = strings.ToLower(strings.TrimSpace(format))
			settings := goreleaserNFPMSettings{
				RPM:  config.RPM,
				Deb:  config.Deb,
				APK:  config.APK,
				MSIX: config.MSIX,
			}
			if override, ok := config.Overrides[format]; ok {
				settings = mergeGoreleaserNFPMSettings(settings, override)
			}
			if !goreleaserPackageSigningConfigured(settings, format) {
				continue
			}
			signals = append(signals, Signal{
				Check: checkArtifactSigning,
				Kind:  goreleaserKindPackageSign,
				Name:  goreleaserNFPMCommand,
				Value: goreleaserSelection(format+"; id="+id, selectors),
				Path:  filePath,
			})
		}
	}
	if srpm.Enabled && srpm.Signature.KeyFile != "" {
		signals = append(signals, Signal{
			Check: checkArtifactSigning,
			Kind:  goreleaserKindPackageSign,
			Name:  goreleaserNFPMCommand,
			Value: "srpm",
			Path:  filePath,
		})
	}
	return signals
}

func mergeGoreleaserNFPMSettings(base, override goreleaserNFPMSettings) goreleaserNFPMSettings {
	if override.RPM.Signature.KeyFile != "" {
		base.RPM.Signature = override.RPM.Signature
	}
	if override.Deb.Signature.KeyFile != "" {
		base.Deb.Signature = override.Deb.Signature
	}
	if override.APK.Signature.KeyFile != "" {
		base.APK.Signature = override.APK.Signature
	}
	if override.MSIX.Signature.PFXFile != "" {
		base.MSIX.Signature = override.MSIX.Signature
	}
	return base
}

func goreleaserPackageSigningConfigured(settings goreleaserNFPMSettings, format string) bool {
	switch format {
	case "rpm":
		return settings.RPM.Signature.KeyFile != ""
	case "deb", "termux.deb":
		return settings.Deb.Signature.KeyFile != ""
	case "apk":
		return settings.APK.Signature.KeyFile != ""
	case "msix":
		return settings.MSIX.Signature.PFXFile != ""
	default:
		return false
	}
}

func effectiveSignIDs(kind, artifacts string, ids []string) []string {
	if kind == goreleaserKindSign && (artifacts == "checksum" || artifacts == "source") {
		return nil
	}
	return ids
}

func effectiveSBOMIDs(artifacts string, ids []string) []string {
	if artifacts == "source" || artifacts == "any" {
		return nil
	}
	return ids
}

func goreleaserSelection(artifacts string, ids []string) string {
	ids = slices.Clone(ids)
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == "" })
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return artifacts
	}
	return artifacts + "; ids=" + strings.Join(ids, ",")
}

func goreleaserDisabled(node yaml.Node) bool {
	if node.Kind != yaml.ScalarNode {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(node.Value), "true")
}
