package main

import "github.com/git-pkgs/brief/kb"

type securityDocumentRules struct {
	threatModel   *kb.ResourceInfo
	audit         *kb.ResourceInfo
	securityAudit *kb.ResourceInfo
	disclosure    *kb.ResourceInfo
}

func newSecurityDocumentRules(knowledge *kb.KnowledgeBase) *securityDocumentRules {
	return &securityDocumentRules{
		threatModel:   knowledge.Resource("security", "threat_model"),
		audit:         knowledge.Resource("security", "audit"),
		securityAudit: knowledge.Resource("security", "security_audit"),
		disclosure:    knowledge.Resource("security", "disclosure"),
	}
}

func (rules *securityDocumentRules) signals(filePath string) []Signal {
	threatModel := matchesResource(rules.threatModel, filePath)
	audit := matchesResource(rules.audit, filePath) || matchesResource(rules.securityAudit, filePath)
	disclosure := matchesResource(rules.disclosure, filePath)
	if !threatModel && !audit && !disclosure {
		return nil
	}
	if !repositoryProjectEvidencePath(filePath) {
		return nil
	}
	var signals []Signal
	if threatModel {
		signals = append(signals, Signal{Check: checkSecurityDocumentation, Kind: "threat-model", Path: filePath})
	}
	if audit {
		signals = append(signals, Signal{Check: checkSecurityDocumentation, Kind: "audit", Path: filePath})
	}
	if disclosure {
		signals = append(signals, Signal{Check: checkSecurityDocumentation, Kind: "disclosure", Path: filePath})
	}
	return signals
}

func matchesResource(resource *kb.ResourceInfo, filePath string) bool {
	return resource != nil && resource.MatchesPath(filePath)
}
