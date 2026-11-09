package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/git-pkgs/brief/kb"
)

const (
	ownershipKindCodeowners  = "codeowners"
	ownershipKindOwner       = "owner"
	ownershipKindMaintainers = "maintainers"
	ownershipKindGovernance  = "governance"
	ownershipKindCoverage    = "coverage"
	ownershipTruncatedName   = "truncated"
	ownershipSummaryName     = "summary"
	codeownersContentBytes   = 3 << 20
)

var codeownerEmailPattern = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}$")

type ownershipRules struct {
	codeowners  *kb.ResourceInfo
	maintainers *kb.ResourceInfo
	governance  *kb.ResourceInfo
}

func newOwnershipRules(knowledge *kb.KnowledgeBase) *ownershipRules {
	return &ownershipRules{
		codeowners:  knowledge.Resource("community", ownershipKindCodeowners),
		maintainers: knowledge.Resource("community", ownershipKindMaintainers),
		governance:  knowledge.Resource("community", ownershipKindGovernance),
	}
}

func (rules *ownershipRules) kind(filePath string) string {
	if rules == nil {
		return ""
	}
	var kind string
	switch {
	case matchesResource(rules.codeowners, filePath):
		kind = ownershipKindCodeowners
	case matchesResource(rules.maintainers, filePath):
		kind = ownershipKindMaintainers
	case matchesResource(rules.governance, filePath):
		kind = ownershipKindGovernance
	}
	if kind == "" || !repositoryProjectEvidencePath(filePath) {
		return ""
	}
	return kind
}

func codeownersSignals(filePath string, data []byte, size int64) []Signal {
	owners := make(map[string]bool)
	var statements []string
	ruleCount := 0
	gitlabSyntax := strings.HasPrefix(strings.ToLower(filePath), ".gitlab/")
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		statement := codeownersStatement(string(line), gitlabSyntax)
		if statement == "" {
			continue
		}
		fields := strings.Fields(statement)
		hasOwner := false
		for _, field := range fields[1:] {
			if codeownerIdentity(field) {
				owners[field] = true
				hasOwner = true
			}
		}
		section := codeownersSection(statement)
		if !section && !gitlabSyntax && !hasOwner {
			continue
		}
		statements = append(statements, strings.Join(fields, " "))
		if !section {
			ruleCount++
		}
	}
	summary := fmt.Sprintf(
		"rules=%d; owners=%d; config=%s",
		ruleCount,
		len(owners),
		contentDigest([]byte(strings.Join(statements, "\n"))),
	)
	signals := []Signal{{
		Check: checkRepositoryOwnership,
		Kind:  ownershipKindCodeowners,
		Name:  ownershipSummaryName,
		Value: summary,
		Path:  filePath,
	}}
	ownerNames := make([]string, 0, len(owners))
	for owner := range owners {
		ownerNames = append(ownerNames, owner)
	}
	sort.Strings(ownerNames)
	for _, owner := range ownerNames {
		signals = append(signals, Signal{
			Check: checkRepositoryOwnership,
			Kind:  ownershipKindOwner,
			Name:  owner,
			Path:  filePath,
		})
	}
	if size > codeownersContentBytes {
		signals = append(signals, Signal{
			Check: checkRepositoryOwnership,
			Kind:  ownershipKindCoverage,
			Name:  ownershipTruncatedName,
			Value: fmt.Sprintf("bytes=%d; limit=%d", size, codeownersContentBytes),
			Path:  filePath,
		})
	}
	return signals
}

func repositoryOwnershipSignals(
	tree fs.FS,
	filePath string,
	size int64,
	rules *ownershipRules,
) ([]Signal, error) {
	kind := rules.kind(filePath)
	if kind == "" {
		return nil, nil
	}
	if kind == ownershipKindCodeowners {
		data, err := readRepositoryFile(tree, filePath, codeownersContentBytes)
		if err != nil {
			return nil, err
		}
		return codeownersSignals(filePath, data, size), nil
	}
	digest, err := ownershipDocumentDigest(tree, filePath)
	if err != nil {
		return nil, err
	}
	return []Signal{{
		Check: checkRepositoryOwnership,
		Kind:  kind,
		Value: digest,
		Path:  filePath,
	}}, nil
}

func ownershipDocumentDigest(tree fs.FS, filePath string) (string, error) {
	hasher := sha256.New()
	err := scanRepositoryFileError(tree, filePath, func(reader io.Reader) error {
		_, err := io.Copy(hasher, reader)
		return err
	})
	digest := hasher.Sum(nil)
	return "sha256:" + hex.EncodeToString(digest[:6]), err
}

func codeownersStatement(line string, gitlabSyntax bool) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, `\#`) {
		return ""
	}
	if gitlabSyntax {
		return line
	}
	fields := strings.Fields(line)
	for index, field := range fields {
		if strings.HasPrefix(field, "#") {
			fields = fields[:index]
			break
		}
	}
	return strings.Join(fields, " ")
}

func codeownerIdentity(value string) bool {
	return (len(value) > 1 && strings.HasPrefix(value, "@")) || codeownerEmailPattern.MatchString(value)
}

func codeownersSection(statement string) bool {
	fields := strings.Fields(statement)
	if len(fields) == 0 {
		return false
	}
	return strings.HasPrefix(strings.TrimPrefix(fields[0], "^"), "[")
}
