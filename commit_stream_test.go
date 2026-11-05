package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/mailmap"
	"github.com/go-git/go-git/v6/plumbing/object"
)

func TestLogWritesCommitEvents(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	gitRun(t, repo, "add", ".")
	gitRunAt(t, repo, "2024-01-01T00:00:00Z", "commit", "-m", "Initial commit")

	writeFile(t, repo, "go.mod", "module example.com/project\n\ngo 1.27\n")
	gitRun(t, repo, "add", ".")
	gitRunAtAs(
		t, repo, "2024-02-01T00:00:00Z",
		"dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com",
		"GitHub", "noreply@github.com",
		"commit", "-m", "Bump dependency",
	)
	addSignedCommit(t, repo, "2024-02-02T00:00:00Z", "Sign release candidate")

	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"log", "--jsonl", "--after", "2024-02-01", "--before", "2024-03-01", repo,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	records := decodeEventRecords(t, stdout.Bytes())
	if len(records) != 2 {
		t.Fatalf("event record count = %d, want 2\n%s", len(records), stdout.String())
	}
	bot := findEventRecord(t, records, "Bump dependency")
	if bot.Author.Name != "dependabot[bot]" || bot.Committer.Name != "GitHub" {
		t.Errorf("bot identities = author %#v, committer %#v", bot.Author, bot.Committer)
	}
	if !containsEvent(bot.Events, checkDependencyUpdateTool, "commit", "Dependabot") {
		t.Errorf("dependency bot event missing: %#v", bot.Events)
	}
	signed := findEventRecord(t, records, "Sign release candidate")
	if !containsEvent(signed.Events, checkSignedCommit, "openpgp", "") {
		t.Errorf("signed commit event missing: %#v", signed.Events)
	}
	if got := signed.CommittedAt.Format(time.RFC3339); got != "2024-02-02T00:00:00Z" {
		t.Errorf("committed_at = %q", got)
	}
}

func TestLogSnapshotsIncludeCommitMetrics(t *testing.T) {
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "Signals Test")
	gitRun(t, repo, "config", "user.email", "signals@example.com")
	gitRun(t, repo, "config", "commit.gpgsign", "false")

	writeFile(t, repo, "README.md", "# example\n")
	writeFile(t, repo, ".mailmap", "Alice <alice@example.org> <old@old.example>\n")
	gitRun(t, repo, "add", ".")
	gitRunAtAs(
		t, repo, "2024-01-10T00:00:00Z",
		"Alice Old", "old@old.example", "Alice Old", "old@old.example",
		"commit", "-m", "Initial commit",
	)

	writeFile(t, repo, "go.mod", "module example.com/project\n\ngo 1.27\n")
	gitRun(t, repo, "add", ".")
	gitRunAtAs(
		t, repo, "2024-01-15T00:00:00Z",
		"dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com",
		"GitHub", "noreply@github.com",
		"commit", "-m", "Bump dependency",
	)

	writeFile(t, repo, "feature.txt", "feature\n")
	gitRun(t, repo, "add", ".")
	gitRunAtAs(
		t, repo, "2024-01-20T00:00:00Z",
		"Bob", "bob@example.org", "Alice", "alice@example.org",
		"commit", "-m", "Add feature (#42)\n\nReviewed-by: Alice <alice@example.org>",
	)

	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"log", "--jsonl", "--snapshots",
		"--after", "2024-02-01", "--before", "2024-03-01", repo,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run log: %v\nstderr:\n%s", err, stderr.String())
	}

	snapshots := decodeSnapshots(t, stdout.Bytes())
	if len(snapshots) != 2 {
		t.Fatalf("snapshot count = %d, want 2\n%s", len(snapshots), stdout.String())
	}
	start := snapshots[0]
	if !start.HistoryComplete || start.MailmapOID == "" {
		t.Errorf("start history metadata = complete %v, mailmap %q", start.HistoryComplete, start.MailmapOID)
	}
	assertCountMetric(t, start.Metrics, checkContributors, "non-bot-authors", "", 2)
	assertCountMetric(t, start.Metrics, checkContributors, "email-domain", "example.org", 2)
	assertCountMetric(t, start.Metrics, checkMaintained, "commits", "", 3)
	assertRatioMetric(t, start.Metrics, checkCodeReview, "proxy-ratio", 1, 2)
	assertCountMetric(t, start.Metrics, checkCodeReview, "author-committer-differ", "", 1)
	assertCountMetric(t, start.Metrics, checkCodeReview, "reviewed-by", "", 1)
	assertCountMetric(t, start.Metrics, checkCodeReview, "squash-pull-request", "", 1)
	assertRatioMetric(t, start.Metrics, checkSignedCommit, "presence-ratio", 0, 3)
	assertDaysMetric(t, start.Metrics, "days-since-commit", 12)
	assertDaysMetric(t, start.Metrics, "repository-age", 22)
	assertDaysMetric(t, snapshots[1].Metrics, "days-since-commit", 41)
}

func TestDependencyBotDoesNotMatchEveryBot(t *testing.T) {
	for _, identity := range []struct {
		name  string
		email string
	}{
		{name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com"},
		{name: "Renovate Docs", email: "renovate-docs@example.com"},
	} {
		if got := dependencyBot(identity.name, identity.email); got != "" {
			t.Errorf("dependencyBot(%q, %q) returned %q", identity.name, identity.email, got)
		}
	}
}

func TestCommitStreamEvictsRollingWindowAndKeepsRepositoryAge(t *testing.T) {
	stream := newCommitStream(mailmap.New())
	stream.add(testCommitAt(t, "2024-01-01T00:00:00Z", "Alice", "alice@example.org", "Initial commit"))
	stream.add(testCommitAt(t, "2024-04-02T00:00:00Z", "Bob", "bob@example.org", "Recent commit"))

	metrics := stream.metricsAt(mustTime(t, "2024-04-03T00:00:00Z"))
	assertCountMetric(t, metrics, checkMaintained, "commits", "", 1)
	assertCountMetric(t, metrics, checkContributors, "non-bot-authors", "", 1)
	assertDaysMetric(t, metrics, "days-since-commit", 1)
	assertDaysMetric(t, metrics, "repository-age", 93)
}

func TestReviewProxiesDoNotTreatSignoffAsReview(t *testing.T) {
	commit := testCommitAt(
		t,
		"2024-01-01T00:00:00Z", "Alice", "alice@example.org",
		"Change dependency\n\nSigned-off-by: Alice <alice@example.org>",
	)
	if got := reviewProxies(mailmap.New(), commit); len(got) != 0 {
		t.Errorf("review proxies = %v", got)
	}
}

func addSignedCommit(t *testing.T, path, date, message string) {
	t.Helper()
	parent := gitOutput(t, path, "rev-parse", "HEAD")
	tree := gitOutput(t, path, "rev-parse", "HEAD^{tree}")
	when, err := time.Parse(time.RFC3339, date)
	if err != nil {
		t.Fatal(err)
	}
	stamp := fmt.Sprintf("%d +0000", when.Unix())
	content := fmt.Sprintf(`tree %s
parent %s
author Release Author <release@example.com> %s
committer Release Committer <release@example.com> %s
gpgsig -----BEGIN PGP SIGNATURE-----
%s
 ZmFrZQ==
 -----END PGP SIGNATURE-----

%s
`, tree, parent, stamp, stamp, " ", message)
	cmd := exec.Command("git", "hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Dir = path
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("write signed commit: %v\n%s", err, output)
	}
	gitRun(t, path, "update-ref", "refs/heads/main", strings.TrimSpace(string(output)))
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func testCommitAt(t *testing.T, date, name, email, message string) *object.Commit {
	t.Helper()
	when := mustTime(t, date)
	identity := object.Signature{Name: name, Email: email, When: when}
	return &object.Commit{Author: identity, Committer: identity, Message: message}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	result, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeEventRecords(t *testing.T, output []byte) []jsonlEventRecord {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(output))
	var records []jsonlEventRecord
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Type != "event" {
			continue
		}
		var record jsonlEventRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func decodeSnapshots(t *testing.T, output []byte) []jsonlSnapshotRecord {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(output))
	var snapshots []jsonlSnapshotRecord
	for decoder.More() {
		var record jsonlSnapshotRecord
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record.Type == "snapshot" {
			snapshots = append(snapshots, record)
		}
	}
	return snapshots
}

func findEventRecord(t *testing.T, records []jsonlEventRecord, subject string) jsonlEventRecord {
	t.Helper()
	for _, record := range records {
		if record.Subject == subject {
			return record
		}
	}
	t.Fatalf("event record for %q not found", subject)
	return jsonlEventRecord{}
}

func containsEvent(events []jsonlSignal, check, kind, name string) bool {
	for _, event := range events {
		if event.Check == check && event.Kind == kind && event.Name == name {
			return true
		}
	}
	return false
}

func assertCountMetric(t *testing.T, metrics []jsonlMetric, check, kind, name string, want int) {
	t.Helper()
	metric := findMetric(t, metrics, check, kind, name)
	if metric.Count == nil || *metric.Count != want {
		t.Errorf("%s/%s %q count = %v, want %d", check, kind, name, metric.Count, want)
	}
}

func assertRatioMetric(t *testing.T, metrics []jsonlMetric, check, kind string, numerator, denominator int) {
	t.Helper()
	metric := findMetric(t, metrics, check, kind, "")
	if metric.Numerator == nil || metric.Denominator == nil ||
		*metric.Numerator != numerator || *metric.Denominator != denominator {
		t.Errorf("%s/%s ratio = %v/%v, want %d/%d", check, kind, metric.Numerator, metric.Denominator, numerator, denominator)
	}
}

func assertDaysMetric(t *testing.T, metrics []jsonlMetric, kind string, want int) {
	t.Helper()
	metric := findMetric(t, metrics, checkMaintained, kind, "")
	if metric.Days == nil || *metric.Days != want {
		t.Errorf("%s/%s days = %v, want %d", checkMaintained, kind, metric.Days, want)
	}
}

func findMetric(t *testing.T, metrics []jsonlMetric, check, kind, name string) jsonlMetric {
	t.Helper()
	for _, metric := range metrics {
		if metric.Check == check && metric.Kind == kind && metric.Name == name {
			return metric
		}
	}
	t.Fatalf("metric %s/%s %q not found: %#v", check, kind, name, metrics)
	return jsonlMetric{}
}
