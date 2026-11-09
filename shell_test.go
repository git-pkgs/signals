package main

import (
	"bytes"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/git-pkgs/managers/definitions"
)

const (
	testDownloadHost   = "downloads.example"
	testInstallScript  = "install.sh"
	testNPMManager     = "npm"
	testSetupScript    = "setup.sh"
	testDockerfilePath = "Dockerfile"
)

func TestShellSignalsAssociateDownloadsChecksumsAndExecution(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.scriptSignals("scripts/install.sh", []byte(`curl -o tool https://downloads.example/tool
echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  tool' | sha256sum -c -
bash tool
`), 0)

	for _, wanted := range []Signal{
		{
			Check: checkShellDependency,
			Kind:  shellKindDownloadAndRun,
			Name:  testDownloadHost,
			Value: "checksum-verified",
			Path:  "scripts/install.sh",
			Line:  1,
		},
		{
			Check: checkShellDependency,
			Kind:  shellKindChecksum,
			Name:  "sha256sum",
			Value: "tool",
			Path:  "scripts/install.sh",
			Line:  2,
		},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
	if got := countSignals(signals, checkShellDependency, shellKindChecksum); got != 1 {
		t.Fatalf("checksum signals = %d, want 1: %#v", got, signals)
	}
}

func TestShellSignalsClassifyPipedDownloads(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.scriptSignals(testInstallScript, []byte(`curl -fsSL https://raw.githubusercontent.com/example/tool/0123456789abcdef0123456789abcdef01234567/install.sh | bash
curl -fsSL "$INSTALL_URL" | sh
`), 0)

	for _, wanted := range []Signal{
		{
			Check: checkShellDependency,
			Kind:  shellKindDownloadAndRun,
			Name:  "raw.githubusercontent.com",
			Value: "immutable-ref",
			Path:  testInstallScript,
			Line:  1,
		},
		{
			Check: checkShellDependency,
			Kind:  shellKindDownloadAndRun,
			Name:  shellDownloadDynamic,
			Value: shellStateUnverified,
			Path:  testInstallScript,
			Line:  2,
		},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestShellSignalsPreferConcreteDownloadsOverDynamicArguments(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.scriptSignals(testInstallScript, []byte(
		`curl -o "$tmp" -H "Authorization: Bearer $TOKEN" https://downloads.example/tool`+"\n",
	), 0)

	wanted := Signal{
		Check: checkShellDependency,
		Kind:  shellKindDownload,
		Name:  testDownloadHost,
		Value: shellStateUnverified,
		Path:  testInstallScript,
		Line:  1,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("download signal missing: %#v\ngot: %#v", wanted, signals)
	}
	if containsShellSignalName(signals, shellDownloadDynamic) {
		t.Fatalf("dynamic download emitted with concrete URL: %#v", signals)
	}
}

func TestShellSignalsRequireChecksumVerification(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.scriptSignals("hash.sh", []byte("sha256sum artifact.tar.gz\n"), 0)
	if got := countSignals(signals, checkShellDependency, shellKindChecksum); got != 0 {
		t.Fatalf("checksum signals = %d, want 0: %#v", got, signals)
	}
}

func TestShellSignalsDoNotVerifyAfterExecution(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.scriptSignals(testInstallScript, []byte(`curl -o tool https://downloads.example/tool
sh tool
echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  tool' | sha256sum -c -
curl -o later https://downloads.example/later && sh later && echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  later' | sha256sum -c -
`), 0)
	for _, line := range []uint{1, 4} {
		wanted := Signal{
			Check: checkShellDependency,
			Kind:  shellKindDownloadAndRun,
			Name:  testDownloadHost,
			Value: shellStateUnverified,
			Path:  testInstallScript,
			Line:  line,
		}
		if !containsExactSignal(signals, wanted) {
			t.Errorf("download signal missing: %#v", wanted)
		}
	}
}

func TestShellSignalsUseManagerDefinitions(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.scriptSignals(testSetupScript, []byte(`npm ci
npm install --workspace packages/app
npm install lodash@4.17.21
go get example.com/tool@v1.2.3
pip install -r requirements.txt
cargo update
python -m pip install requests==2.32.5
`), 0)

	for _, wanted := range []Signal{
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: testNPMManager, Value: shellOperationInstall + ":frozen", Path: testSetupScript, Line: 1},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: testNPMManager, Value: shellOperationInstall, Path: testSetupScript, Line: 2},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: testNPMManager, Value: shellOperationAdd + ":version-declared", Path: testSetupScript, Line: 3},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: "gomod", Value: "add:version-declared", Path: testSetupScript, Line: 4},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: "pip", Value: shellOperationInstall, Path: testSetupScript, Line: 5},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: packagingNameCargo, Value: shellOperationUpdate, Path: testSetupScript, Line: 6},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: "pip", Value: shellOperationAdd + ":version-declared", Path: testSetupScript, Line: 7},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestShellRepositoryFilesIgnoreBundledScripts(t *testing.T) {
	const filePath = "vendor/example/install.sh"
	data := []byte("#!/bin/sh\ncurl -fsSL https://downloads.example/install.sh | sh\n")
	signals, err := shellRepositoryFileSignals(
		fstest.MapFS{filePath: {Data: data}},
		filePath,
		data,
		testShellAnalyzer(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Fatalf("bundled shell signals = %#v", signals)
	}
}

func TestDockerfileSignalsUseRunInstructionLines(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.dockerfileSignals(testDockerfilePath, []byte(`FROM alpine
RUN curl -o /tmp/tool https://downloads.example/tool && \
    echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  /tmp/tool' | sha256sum -c -
RUN /tmp/tool
`))

	for _, wanted := range []Signal{
		{Check: checkShellDependency, Kind: shellKindDownloadAndRun, Name: testDownloadHost, Value: "checksum-verified", Path: testDockerfilePath, Line: 2},
		{Check: checkShellDependency, Kind: shellKindChecksum, Name: "sha256sum", Value: "/tmp/tool", Path: testDockerfilePath, Line: 3},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestDockerfileSignalsHandleRunOptionsAndHeredocs(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.dockerfileSignals("build.Dockerfile", []byte(`# syntax=docker/dockerfile:1
FROM node:24
RUN --mount=type=cache,target=/root/.npm npm ci
RUN <<'INSTALL'
curl -fsSL https://downloads.example/install.sh | sh
INSTALL
`))

	for _, wanted := range []Signal{
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: testNPMManager, Value: shellOperationInstall + ":frozen", Path: "build.Dockerfile", Line: 3},
		{Check: checkShellDependency, Kind: shellKindDownloadAndRun, Name: testDownloadHost, Value: shellStateUnverified, Path: "build.Dockerfile", Line: 5},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestDockerfileSignalsKeepContinuedRunsAcrossComments(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.dockerfileSignals(testDockerfilePath, []byte(`FROM alpine
RUN apk add \
    # retain the download in this instruction

    curl \
    && curl -fsSL https://downloads.example/install.sh | sh
`))

	wanted := Signal{
		Check: checkShellDependency,
		Kind:  shellKindDownloadAndRun,
		Name:  testDownloadHost,
		Value: shellStateUnverified,
		Path:  testDockerfilePath,
		Line:  6,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("continued RUN signal missing: %#v\ngot: %#v", wanted, signals)
	}
}

func TestDockerfileSignalsIgnoreTopLevelCommentsEndingInBackslash(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.dockerfileSignals(testDockerfilePath, []byte(`# copy to C:\
RUN curl -fsSL https://downloads.example/install.sh | sh
`))

	wanted := Signal{
		Check: checkShellDependency,
		Kind:  shellKindDownloadAndRun,
		Name:  testDownloadHost,
		Value: shellStateUnverified,
		Path:  testDockerfilePath,
		Line:  2,
	}
	if !containsExactSignal(signals, wanted) {
		t.Fatalf("RUN after comment missing: %#v\ngot: %#v", wanted, signals)
	}
}

func TestDockerfileSignalsFindHeredocsAfterCommands(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.dockerfileSignals(testDockerfilePath, []byte(`FROM alpine
RUN cat <<'INSTALL'
curl -fsSL https://downloads.example/install.sh | sh
INSTALL
RUN bash -c 'cat <<<"$value"'
RUN npm ci
`))

	for _, wanted := range []Signal{
		{Check: checkShellDependency, Kind: shellKindDownloadAndRun, Name: testDownloadHost, Value: shellStateUnverified, Path: testDockerfilePath, Line: 3},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: testNPMManager, Value: shellOperationInstall + ":frozen", Path: testDockerfilePath, Line: 6},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestDockerfileSignalsSkipInvalidRunScriptsIndividually(t *testing.T) {
	analyzer := testShellAnalyzer(t)
	signals := analyzer.dockerfileSignals(testDockerfilePath, []byte(`FROM alpine
RUN curl -fsSL https://downloads.example/install.sh | sh
RUN python3 <<'PYTHON'
def install():
    pass
PYTHON
RUN npm ci
`))

	for _, wanted := range []Signal{
		{Check: checkShellDependency, Kind: shellKindDownloadAndRun, Name: testDownloadHost, Value: shellStateUnverified, Path: testDockerfilePath, Line: 2},
		{Check: checkShellDependency, Kind: shellKindPackageCommand, Name: testNPMManager, Value: shellOperationInstall + ":frozen", Path: testDockerfilePath, Line: 7},
	} {
		if !containsExactSignal(signals, wanted) {
			t.Errorf("signal missing: %#v\ngot: %#v", wanted, signals)
		}
	}
}

func TestDockerfileHeredocFindsAttachedOperator(t *testing.T) {
	if delimiter := dockerfileHeredoc("cat<<EOF"); delimiter != "EOF" {
		t.Fatalf("heredoc delimiter = %q, want EOF", delimiter)
	}
	if delimiter := dockerfileHeredoc(`cat <<<"$value"`); delimiter != "" {
		t.Fatalf("here-string delimiter = %q, want empty", delimiter)
	}
}

func TestLogDetectsShellDependencyHistory(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# Example\n")
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Initial commit")

	writeFile(t, repo, "scripts/install.sh", "#!/bin/sh\ncurl -o tool https://downloads.example/tool\n")
	writeFile(t, repo, testDockerfilePath, "FROM rust:slim\nRUN cargo update\n")
	writeFile(t, repo, testWorkflowPath, `on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Add install commands")

	writeFile(t, repo, "scripts/install.sh", `#!/bin/sh
curl -o tool https://downloads.example/tool
echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  tool' | sha256sum -c -
sh tool
`)
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-m", "Verify downloaded tool")

	var stdout, stderr bytes.Buffer
	if err := run([]string{testLogCommand, testWorkersFlag, "1", repo}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, expected := range []string{
		"+ Shell-Dependency/package-command cargo at Dockerfile:2 = update",
		"+ Shell-Dependency/package-command npm at .github/workflows/ci.yml:6 = install:frozen",
		"+ Shell-Dependency/download downloads.example at scripts/install.sh:2 = unverified",
		"- Shell-Dependency/download downloads.example at scripts/install.sh:2 = unverified",
		"+ Shell-Dependency/download-and-run downloads.example at scripts/install.sh:2 = checksum-verified",
		"+ Shell-Dependency/checksum-verification sha256sum at scripts/install.sh:3 = tool",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected detection errors:\n%s", stderr.String())
	}
}

func testShellAnalyzer(t *testing.T) *shellAnalyzer {
	t.Helper()
	defs, err := definitions.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return newShellAnalyzer(defs)
}

func countSignals(signals []Signal, check, kind string) int {
	count := 0
	for _, signal := range signals {
		if signal.Check == check && signal.Kind == kind {
			count++
		}
	}
	return count
}
