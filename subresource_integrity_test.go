package main

import (
	"strings"
	"testing"
)

const (
	testCDNScript  = "https://cdn.example/app.js"
	testMarkupPath = "templates/index.html.erb"
	testSRI        = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="
)

func TestSubresourceIntegritySignals(t *testing.T) {
	t.Parallel()

	markup := `<script src="https://cdn.example/app.js" integrity="sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="></script>
<script src="//cdn.example/missing.js"></script>
<script src="https://cdn.example/invalid.js" integrity="sha256-not-base64"></script>
<script src="/local.js"></script>
<link rel="stylesheet" href="https://cdn.example/app.css">
<link rel="icon" href="https://cdn.example/favicon.ico">
<link rel="icon" href="https://cdn.example/protected-icon.ico" integrity="sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=">
`
	signals, err := subresourceIntegritySignals(testMarkupPath, strings.NewReader(markup))
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []Signal{
		{Check: checkSubresourceIntegrity, Kind: "protected", Name: testCDNScript, Value: testSRI, Path: testMarkupPath},
		{Check: checkSubresourceIntegrity, Kind: "missing", Name: "//cdn.example/missing.js", Path: testMarkupPath},
		{Check: checkSubresourceIntegrity, Kind: signalInvalid, Name: "https://cdn.example/invalid.js", Path: testMarkupPath},
		{Check: checkSubresourceIntegrity, Kind: "missing", Name: "https://cdn.example/app.css", Path: testMarkupPath},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("missing %#v in %#v", wanted, signals)
		}
	}
	if len(signals) != 4 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestSubresourceMarkupPath(t *testing.T) {
	t.Parallel()

	for _, filePath := range []string{"index.html", "views/app.html.erb", "templates/base.jinja", "src/App.vue"} {
		if !subresourceMarkupPath(filePath) {
			t.Errorf("%s was not recognized as markup", filePath)
		}
	}
	for _, filePath := range []string{"main.go", "vendor/index.html"} {
		if subresourceMarkupPath(filePath) {
			t.Errorf("%s was recognized as project markup", filePath)
		}
	}
}
