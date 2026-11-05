package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/mailmap"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

const (
	checkCodeReview   = "Code-Review"
	checkContributors = "Contributors"
	checkMaintained   = "Maintained"
	checkSignedCommit = "Signed-Commit"
	day               = 24 * time.Hour
	metricWindow      = 90 * day
	metricWindowName  = "90d"
)

var reviewProxyKinds = []string{
	"acked-by",
	"author-committer-differ",
	"merge-pull-request",
	"reviewed-by",
	"squash-pull-request",
	"tested-by",
}

type jsonlEventRecord struct {
	Type        string        `json:"type"`
	Commit      string        `json:"commit"`
	Author      jsonlAuthor   `json:"author"`
	Committer   jsonlAuthor   `json:"committer"`
	AuthoredAt  time.Time     `json:"authored_at"`
	CommittedAt time.Time     `json:"committed_at"`
	Subject     string        `json:"subject"`
	Events      []jsonlSignal `json:"events"`
}

type jsonlMetric struct {
	Check       string `json:"check"`
	Kind        string `json:"kind"`
	Name        string `json:"name,omitempty"`
	Window      string `json:"window,omitempty"`
	Count       *int   `json:"count,omitempty"`
	Numerator   *int   `json:"numerator,omitempty"`
	Denominator *int   `json:"denominator,omitempty"`
	Days        *int   `json:"days,omitempty"`
}

type commitWindowEntry struct {
	committedAt   time.Time
	contributor   string
	domain        string
	human         bool
	signed        bool
	reviewProxies []string
}

type commitStream struct {
	mailmap              *mailmap.Mailmap
	entries              []commitWindowEntry
	entryStart           int
	contributors         map[string]int
	domains              map[string]int
	reviewProxyCounts    map[string]int
	commits              int
	humanCommits         int
	reviewedHumanCommits int
	signedCommits        int
	firstCommitAt        time.Time
	lastCommitAt         time.Time
}

type snapshotCollector struct {
	enabled      bool
	stream       *commitStream
	after        time.Time
	before       time.Time
	start        boundarySnapshot
	end          boundarySnapshot
	startWritten bool
	endCaptured  bool
}

func newSnapshotCollector(
	repo *git.Repository,
	local *localDetectors,
	uri string,
	opts LogOptions,
	cache *blobCache,
	stats *scanStats,
) (*snapshotCollector, error) {
	collector := &snapshotCollector{enabled: opts.Snapshots}
	if !opts.Snapshots {
		return collector, nil
	}
	after, err := time.Parse(time.DateOnly, opts.After)
	if err != nil {
		return nil, err
	}
	before, err := time.Parse(time.DateOnly, opts.Before)
	if err != nil {
		return nil, err
	}
	mm, mailmapOID, err := loadMailmap(repo, opts.Ref, cache)
	if err != nil {
		return nil, err
	}
	complete, err := historyIsComplete(repo, opts.Since)
	if err != nil {
		return nil, err
	}
	start, err := loadBoundarySnapshot(repo, local, uri, opts.Ref, "start", opts.After, cache, stats)
	if err != nil {
		return nil, err
	}
	end, err := loadBoundarySnapshot(repo, local, uri, opts.Ref, "end", opts.Before, cache, stats)
	if err != nil {
		return nil, err
	}
	start.historyComplete = complete
	start.mailmapOID = mailmapOID
	end.historyComplete = complete
	end.mailmapOID = mailmapOID
	collector.stream = newCommitStream(mm)
	collector.after = after
	collector.before = before
	collector.start = start
	collector.end = end
	return collector, nil
}

func (c *snapshotCollector) beforeCommit(writer io.Writer, commit *object.Commit, jsonl bool) error {
	if !c.enabled {
		return nil
	}
	if !c.startWritten && !commit.Committer.When.Before(c.after) {
		c.start.metrics = c.stream.metricsAt(c.after)
		if err := writeBoundarySnapshot(writer, c.start, jsonl); err != nil {
			return err
		}
		c.startWritten = true
	}
	if !c.endCaptured && !commit.Committer.When.Before(c.before) {
		c.end.metrics = c.stream.metricsAt(c.before)
		c.endCaptured = true
	}
	return nil
}

func (c *snapshotCollector) add(commit *object.Commit) {
	if c.enabled {
		c.stream.add(commit)
	}
}

func (c *snapshotCollector) finish(writer io.Writer, jsonl bool) error {
	if !c.enabled {
		return nil
	}
	if !c.startWritten {
		c.start.metrics = c.stream.metricsAt(c.after)
		if err := writeBoundarySnapshot(writer, c.start, jsonl); err != nil {
			return err
		}
	}
	if !c.endCaptured {
		c.end.metrics = c.stream.metricsAt(c.before)
	}
	return writeBoundarySnapshot(writer, c.end, jsonl)
}

func newCommitStream(mm *mailmap.Mailmap) *commitStream {
	return &commitStream{
		mailmap:           mm,
		contributors:      make(map[string]int),
		domains:           make(map[string]int),
		reviewProxyCounts: make(map[string]int),
	}
}

func (s *commitStream) add(commit *object.Commit) {
	s.evictBefore(commit.Committer.When.Add(-metricWindow))
	entry := commitWindowEntry{
		committedAt: commit.Committer.When,
		human:       !isBotIdentity(commit.Author.Name, commit.Author.Email),
		signed:      commit.Signature != "" || commit.SignatureSHA256 != "",
	}
	entry.contributor, entry.domain = canonicalIdentity(s.mailmap, commit.Author.Name, commit.Author.Email)
	entry.reviewProxies = reviewProxies(s.mailmap, commit)

	if s.firstCommitAt.IsZero() || commit.Committer.When.Before(s.firstCommitAt) {
		s.firstCommitAt = commit.Committer.When
	}
	if s.lastCommitAt.IsZero() || commit.Committer.When.After(s.lastCommitAt) {
		s.lastCommitAt = commit.Committer.When
	}
	s.entries = append(s.entries, entry)
	s.commits++
	if entry.signed {
		s.signedCommits++
	}
	if !entry.human {
		return
	}
	s.humanCommits++
	if entry.contributor != "" {
		if s.contributors[entry.contributor] == 0 && entry.domain != "" {
			s.domains[entry.domain]++
		}
		s.contributors[entry.contributor]++
	}
	if len(entry.reviewProxies) > 0 {
		s.reviewedHumanCommits++
	}
	for _, proxy := range entry.reviewProxies {
		s.reviewProxyCounts[proxy]++
	}
}

func (s *commitStream) metricsAt(asOf time.Time) []jsonlMetric {
	s.evictBefore(asOf.Add(-metricWindow))
	metrics := []jsonlMetric{
		metricCount(checkContributors, "non-bot-authors", metricWindowName, len(s.contributors)),
	}
	domains := make([]string, 0, len(s.domains))
	for domain := range s.domains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		metrics = append(metrics, metricNamedCount(checkContributors, "email-domain", domain, metricWindowName, s.domains[domain]))
	}
	metrics = append(metrics,
		metricCount(checkMaintained, "commits", metricWindowName, s.commits),
		metricRatio(checkCodeReview, "proxy-ratio", metricWindowName, s.reviewedHumanCommits, s.humanCommits),
	)
	for _, proxy := range reviewProxyKinds {
		metrics = append(metrics, metricCount(checkCodeReview, proxy, metricWindowName, s.reviewProxyCounts[proxy]))
	}
	metrics = append(metrics, metricRatio(checkSignedCommit, "presence-ratio", metricWindowName, s.signedCommits, s.commits))
	if !s.lastCommitAt.IsZero() && !asOf.Before(s.lastCommitAt) {
		metrics = append(metrics, metricDays(checkMaintained, "days-since-commit", daysBetween(s.lastCommitAt, asOf)))
	}
	if !s.firstCommitAt.IsZero() && !asOf.Before(s.firstCommitAt) {
		metrics = append(metrics, metricDays(checkMaintained, "repository-age", daysBetween(s.firstCommitAt, asOf)))
	}
	return metrics
}

func (s *commitStream) evictBefore(cutoff time.Time) {
	for s.entryStart < len(s.entries) && s.entries[s.entryStart].committedAt.Before(cutoff) {
		entry := s.entries[s.entryStart]
		s.entryStart++
		s.commits--
		if entry.signed {
			s.signedCommits--
		}
		if !entry.human {
			continue
		}
		s.humanCommits--
		if entry.contributor != "" {
			s.contributors[entry.contributor]--
			if s.contributors[entry.contributor] == 0 {
				delete(s.contributors, entry.contributor)
				if entry.domain != "" {
					s.domains[entry.domain]--
					if s.domains[entry.domain] == 0 {
						delete(s.domains, entry.domain)
					}
				}
			}
		}
		if len(entry.reviewProxies) > 0 {
			s.reviewedHumanCommits--
		}
		for _, proxy := range entry.reviewProxies {
			s.reviewProxyCounts[proxy]--
		}
	}
	if s.entryStart > 1024 && s.entryStart*2 > len(s.entries) {
		s.entries = append([]commitWindowEntry(nil), s.entries[s.entryStart:]...)
		s.entryStart = 0
	}
}

func commitEvents(commit *object.Commit) []jsonlSignal {
	var events []jsonlSignal
	if tool := dependencyBot(commit.Author.Name, commit.Author.Email); tool != "" {
		events = append(events, jsonlSignal{Check: checkDependencyUpdateTool, Kind: "commit", Name: tool})
	}
	if commit.Signature != "" || commit.SignatureSHA256 != "" {
		events = append(events, jsonlSignal{Check: checkSignedCommit, Kind: signatureKind(commit)})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Check != events[j].Check {
			return events[i].Check < events[j].Check
		}
		if events[i].Kind != events[j].Kind {
			return events[i].Kind < events[j].Kind
		}
		return events[i].Name < events[j].Name
	})
	return events
}

func dependencyBot(name, email string) string {
	identities := []string{strings.ToLower(strings.TrimSpace(name))}
	local, domain, _ := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	identities = append(identities, local)
	if _, suffix, found := strings.Cut(local, "+"); found {
		identities = append(identities, suffix)
	}
	if domain != "" {
		identities = append(identities, domain)
	}
	for _, candidate := range []struct {
		identities []string
		name       string
	}{
		{identities: []string{"dependabot", "dependabot[bot]"}, name: "Dependabot"},
		{identities: []string{"renovate", "renovate[bot]", "renovate-bot", "renovate bot", "renovateapp.com"}, name: "Renovate"},
		{identities: []string{"scala-steward", "scala-steward[bot]", "scala steward"}, name: "Scala Steward"},
		{identities: []string{"greenkeeper", "greenkeeper[bot]", "greenkeeper.io"}, name: "Greenkeeper"},
	} {
		for _, identity := range identities {
			for _, candidateIdentity := range candidate.identities {
				if identity == candidateIdentity {
					return candidate.name
				}
			}
		}
	}
	return ""
}

func isBotIdentity(name, email string) bool {
	identity := strings.ToLower(name + " " + email)
	return strings.Contains(identity, "[bot]") || dependencyBot(name, email) != ""
}

func signatureKind(commit *object.Commit) string {
	signature := commit.Signature + commit.SignatureSHA256
	switch {
	case strings.Contains(signature, "BEGIN PGP SIGNATURE"):
		return "openpgp"
	case strings.Contains(signature, "BEGIN SSH SIGNATURE"):
		return "ssh"
	case strings.Contains(signature, "BEGIN SIGNED MESSAGE"), strings.Contains(signature, "BEGIN CERTIFICATE"):
		return "x509"
	default:
		return "unknown"
	}
}

func canonicalIdentity(mm *mailmap.Mailmap, name, email string) (string, string) {
	name, email = mm.Resolve(name, email)
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		_, domain, found := strings.Cut(email, "@")
		if !found || domain == "users.noreply.github.com" {
			domain = ""
		}
		return "email:" + email, domain
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", ""
	}
	return "name:" + name, ""
}

func reviewProxies(mm *mailmap.Mailmap, commit *object.Commit) []string {
	proxies := make(map[string]bool)
	author, _ := canonicalIdentity(mm, commit.Author.Name, commit.Author.Email)
	committer, _ := canonicalIdentity(mm, commit.Committer.Name, commit.Committer.Email)
	if author != "" && committer != "" && author != committer {
		proxies["author-committer-differ"] = true
	}
	subject := commitSubject(commit.Message)
	if strings.HasPrefix(subject, "Merge pull request #") {
		proxies["merge-pull-request"] = true
	}
	if hasSquashPRSuffix(subject) {
		proxies["squash-pull-request"] = true
	}
	for _, line := range strings.Split(commit.Message, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		for _, trailer := range []string{"reviewed-by:", "acked-by:", "tested-by:"} {
			if strings.HasPrefix(line, trailer) {
				proxies[strings.TrimSuffix(trailer, ":")] = true
			}
		}
	}
	result := make([]string, 0, len(proxies))
	for proxy := range proxies {
		result = append(result, proxy)
	}
	sort.Strings(result)
	return result
}

func hasSquashPRSuffix(subject string) bool {
	end := strings.LastIndex(subject, "(#")
	if end < 0 || !strings.HasSuffix(subject, ")") {
		return false
	}
	number := subject[end+2 : len(subject)-1]
	if number == "" {
		return false
	}
	for _, char := range number {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func loadMailmap(repo *git.Repository, ref string, cache *blobCache) (*mailmap.Mailmap, string, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return nil, "", err
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, "", err
	}
	file, err := commit.File(".mailmap")
	if errors.Is(err, object.ErrFileNotFound) {
		return mailmap.New(), "", nil
	}
	if err != nil {
		return nil, "", err
	}
	reader, err := cache.reader(file)
	if err != nil {
		return nil, "", err
	}
	mm, parseErr := mailmap.Parse(reader)
	err = errors.Join(parseErr, reader.Close())
	if err != nil {
		return nil, "", fmt.Errorf("parse .mailmap: %w", err)
	}
	return mm, file.Hash.String(), nil
}

func historyIsComplete(repo *git.Repository, since string) (bool, error) {
	shallow, err := repo.Storer.Shallow()
	if err != nil {
		return false, err
	}
	return since == "" && len(shallow) == 0, nil
}

func writeJSONLEventRecord(writer io.Writer, commit *object.Commit, events []jsonlSignal) error {
	record := jsonlEventRecord{
		Type:        "event",
		Commit:      commit.Hash.String(),
		Author:      jsonlAuthor{Name: commit.Author.Name, Email: commit.Author.Email},
		Committer:   jsonlAuthor{Name: commit.Committer.Name, Email: commit.Committer.Email},
		AuthoredAt:  commit.Author.When,
		CommittedAt: commit.Committer.When,
		Subject:     commitSubject(commit.Message),
		Events:      events,
	}
	return json.NewEncoder(writer).Encode(record)
}

func formatMetric(metric jsonlMetric) string {
	name := metric.Check + "/" + metric.Kind
	if metric.Name != "" {
		name += " " + metric.Name
	}
	suffix := ""
	if metric.Window != "" {
		suffix = " (" + metric.Window + ")"
	}
	switch {
	case metric.Count != nil:
		return fmt.Sprintf("%s = %d%s", name, *metric.Count, suffix)
	case metric.Numerator != nil && metric.Denominator != nil:
		return fmt.Sprintf("%s = %d/%d%s", name, *metric.Numerator, *metric.Denominator, suffix)
	case metric.Days != nil:
		return fmt.Sprintf("%s = %d days", name, *metric.Days)
	default:
		return name
	}
}

func metricCount(check, kind, window string, count int) jsonlMetric {
	return jsonlMetric{Check: check, Kind: kind, Window: window, Count: intPointer(count)}
}

func metricNamedCount(check, kind, name, window string, count int) jsonlMetric {
	metric := metricCount(check, kind, window, count)
	metric.Name = name
	return metric
}

func metricRatio(check, kind, window string, numerator, denominator int) jsonlMetric {
	return jsonlMetric{
		Check:       check,
		Kind:        kind,
		Window:      window,
		Numerator:   intPointer(numerator),
		Denominator: intPointer(denominator),
	}
}

func metricDays(check, kind string, days int) jsonlMetric {
	return jsonlMetric{Check: check, Kind: kind, Days: intPointer(days)}
}

func intPointer(value int) *int {
	return &value
}

func daysBetween(start, end time.Time) int {
	return int(end.Sub(start) / day)
}

func commitSubject(message string) string {
	subject, _, _ := strings.Cut(message, "\n")
	return subject
}
