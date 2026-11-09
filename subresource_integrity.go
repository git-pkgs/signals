package main

import (
	"errors"
	"io"
	"strings"

	"github.com/git-pkgs/integrity"
	gitlanguages "github.com/git-pkgs/languages"
	"github.com/git-pkgs/roles"
	"golang.org/x/net/html"
)

const (
	htmlLinkElement        = "link"
	htmlScriptElement      = "script"
	subresourceMarkupBytes = 8 << 20
)

var subresourceMarkupLanguages = gitlanguages.NewSet(
	gitlanguages.Astro,
	gitlanguages.EJS,
	gitlanguages.ERB,
	gitlanguages.GoTemplate,
	gitlanguages.Handlebars,
	gitlanguages.HTML,
	gitlanguages.HTMLPlusECR,
	gitlanguages.HTMLPlusEEX,
	gitlanguages.HTMLPlusRazor,
	gitlanguages.JavaScriptPlusERB,
	gitlanguages.Jinja,
	gitlanguages.JSX,
	gitlanguages.Liquid,
	gitlanguages.Mustache,
	gitlanguages.Nunjucks,
	gitlanguages.PHP,
	gitlanguages.Svelte,
	gitlanguages.TSX,
	gitlanguages.Twig,
	gitlanguages.Vue,
	gitlanguages.XML,
)

func subresourceMarkupPath(filePath string) bool {
	labels, err := roles.Match(filePath)
	if err == nil && labels.BundledOrDerived() {
		return false
	}
	candidates := gitlanguages.AnalyzePath(filePath).Candidates
	return !candidates.Intersect(subresourceMarkupLanguages).Empty()
}

func subresourceIntegritySignals(filePath string, reader io.Reader) ([]Signal, error) {
	tokenizer := html.NewTokenizer(io.LimitReader(reader, subresourceMarkupBytes))
	var signals []Signal
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			sortSignals(signals)
			return deduplicateSignals(signals), nil
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			signal, ok := subresourceIntegritySignal(filePath, token)
			if ok {
				signals = append(signals, signal)
			}
		}
	}
}

func subresourceIntegritySignal(filePath string, token html.Token) (Signal, bool) {
	if token.Data != htmlScriptElement && token.Data != htmlLinkElement {
		return Signal{}, false
	}
	attributes := make(map[string]string, len(token.Attr))
	for _, attribute := range token.Attr {
		attributes[attribute.Key] = attribute.Val
	}
	url := attributes["src"]
	if token.Data == htmlLinkElement {
		url = attributes["href"]
	}
	if !remoteSubresource(url) {
		return Signal{}, false
	}
	if token.Data == htmlLinkElement && !integrityLinkRelation(attributes["rel"]) {
		return Signal{}, false
	}
	metadata, hasIntegrity := attributes["integrity"]
	if !hasIntegrity {
		return Signal{Check: checkSubresourceIntegrity, Kind: "missing", Name: url, Path: filePath}, true
	}
	parsed, err := integrity.ParseSRI(metadata)
	if err != nil {
		return Signal{Check: checkSubresourceIntegrity, Kind: signalInvalid, Name: url, Path: filePath}, true
	}
	return Signal{
		Check: checkSubresourceIntegrity,
		Kind:  "protected",
		Name:  url,
		Value: integrity.FormatSRI(parsed),
		Path:  filePath,
	}, true
}

func remoteSubresource(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") ||
		strings.HasPrefix(url, "//")
}

func integrityLinkRelation(value string) bool {
	for relation := range strings.FieldsSeq(strings.ToLower(value)) {
		switch relation {
		case "modulepreload", "preload", "stylesheet":
			return true
		}
	}
	return false
}
