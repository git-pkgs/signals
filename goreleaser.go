package main

import (
	"path"
	"strings"

	"github.com/git-pkgs/roles"
	"go.yaml.in/yaml/v3"
)

const (
	goreleaserKindSign       = "artifact"
	goreleaserKindDockerSign = "container"
	goreleaserKindBinarySign = "binary"
	goreleaserKindSBOM       = "GoReleaser"
	goreleaserGPGCommand     = "gpg"
	goreleaserArtifactsNone  = "none"
)

type goreleaserConfig struct {
	Signs       []goreleaserSign `yaml:"signs"`
	DockerSigns []goreleaserSign `yaml:"docker_signs"`
	BinarySigns []goreleaserSign `yaml:"binary_signs"`
	SBOMs       []goreleaserSBOM `yaml:"sboms"`
}

type goreleaserSign struct {
	Cmd       string `yaml:"cmd"`
	Artifacts string `yaml:"artifacts"`
}

type goreleaserSBOM struct {
	Cmd       string    `yaml:"cmd"`
	Artifacts string    `yaml:"artifacts"`
	Disable   yaml.Node `yaml:"disable"`
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
			Value: artifacts,
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
		if artifacts == "none" {
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
			Value: artifacts,
			Path:  filePath,
		})
	}
	return signals
}

func goreleaserDisabled(node yaml.Node) bool {
	if node.Kind != yaml.ScalarNode {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(node.Value), "true")
}
