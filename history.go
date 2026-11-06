package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	githistory "github.com/git-pkgs/history"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

type LogOptions struct {
	Ref       string
	Since     string
	After     string
	Before    string
	Workers   int
	Progress  int
	Stats     bool
	JSONL     bool
	Snapshots bool
}

type signalChange struct {
	Marker byte
	Signal Signal
}

type jsonlRecord struct {
	Type        string        `json:"type"`
	Commit      string        `json:"commit"`
	Author      jsonlAuthor   `json:"author"`
	Committer   jsonlAuthor   `json:"committer"`
	AuthoredAt  time.Time     `json:"authored_at"`
	CommittedAt time.Time     `json:"committed_at"`
	Subject     string        `json:"subject"`
	Changes     []jsonlChange `json:"changes,omitempty"`
	Errors      []errorChange `json:"errors,omitempty"`
}

type jsonlAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type jsonlChange struct {
	Change string `json:"change"`
	Check  string `json:"check"`
	Kind   string `json:"kind,omitempty"`
	Name   string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
	Path   string `json:"path,omitempty"`
	Line   uint   `json:"line,omitempty"`
}

type jsonlSignal struct {
	Check string `json:"check"`
	Kind  string `json:"kind,omitempty"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	Path  string `json:"path,omitempty"`
	Line  uint   `json:"line,omitempty"`
}

type jsonlSnapshotRecord struct {
	Type            string        `json:"type"`
	Boundary        string        `json:"boundary"`
	Date            string        `json:"date"`
	Commit          string        `json:"commit,omitempty"`
	Author          *jsonlAuthor  `json:"author,omitempty"`
	Committer       *jsonlAuthor  `json:"committer,omitempty"`
	AuthoredAt      *time.Time    `json:"authored_at,omitempty"`
	CommittedAt     *time.Time    `json:"committed_at,omitempty"`
	Subject         string        `json:"subject,omitempty"`
	Signals         []jsonlSignal `json:"signals"`
	Metrics         []jsonlMetric `json:"metrics"`
	HistoryComplete bool          `json:"history_complete"`
	MailmapOID      string        `json:"mailmap_oid,omitempty"`
	Errors          []errorChange `json:"errors,omitempty"`
}

type boundarySnapshot struct {
	boundary        string
	date            string
	commit          *object.Commit
	state           commitState
	metrics         []jsonlMetric
	historyComplete bool
	mailmapOID      string
}

type commitState struct {
	signals        map[string]Signal
	errors         map[string]string
	languages      languageInventory
	briefLanguages []string
	reuseFiles     map[string]reuseFile
	reuseActive    bool
}

type commitStateStore struct {
	states    map[plumbing.Hash]commitState
	remaining map[plumbing.Hash]int
}

type detectorStats struct {
	runs     int
	full     int
	partial  int
	skipped  int
	duration time.Duration
}

type scanStats struct {
	started   time.Time
	commits   int
	languages time.Duration
	detectors map[string]*detectorStats
	cache     *blobCache
}

func newScanStats(cache *blobCache) *scanStats {
	stats := &scanStats{
		started:   time.Now(),
		detectors: make(map[string]*detectorStats, len(scorecardDetectors)),
		cache:     cache,
	}
	for _, detector := range scorecardDetectors {
		stats.detectors[detector.name] = &detectorStats{}
	}
	for _, name := range localDetectorNames {
		stats.detectors[name] = &detectorStats{}
	}
	return stats
}

func planCommitWalk(repo *githistory.Repo, opts LogOptions) (githistory.CommitOptions, *commitStateStore, error) {
	walk := githistory.CommitOptions{
		Ref:     opts.Ref,
		Since:   opts.Since,
		Merges:  true,
		Workers: opts.Workers,
	}
	hashes, err := repo.CommitHashes(walk)
	if err != nil {
		return githistory.CommitOptions{}, nil, err
	}
	remaining, err := firstParentChildCounts(repo.Repository(), hashes)
	if err != nil {
		return githistory.CommitOptions{}, nil, err
	}
	walk.Hashes = hashes
	return walk, newCommitStateStore(remaining), nil
}

func firstParentChildCounts(repo *git.Repository, hashes []plumbing.Hash) (map[plumbing.Hash]int, error) {
	counts := make(map[plumbing.Hash]int)
	for _, hash := range hashes {
		commit, err := repo.CommitObject(hash)
		if err != nil {
			return nil, err
		}
		if len(commit.ParentHashes) > 0 {
			counts[commit.ParentHashes[0]]++
		}
	}
	return counts, nil
}

func newCommitStateStore(remaining map[plumbing.Hash]int) *commitStateStore {
	return &commitStateStore{
		states:    make(map[plumbing.Hash]commitState),
		remaining: remaining,
	}
}

func (s *commitStateStore) get(hash plumbing.Hash) (commitState, bool) {
	state, ok := s.states[hash]
	return state, ok
}

func (s *commitStateStore) retain(hash plumbing.Hash, state commitState) {
	if s.remaining[hash] == 0 {
		return
	}
	s.states[hash] = state
}

func (s *commitStateStore) release(hash plumbing.Hash) {
	s.remaining[hash]--
	if s.remaining[hash] > 0 {
		return
	}
	delete(s.remaining, hash)
	delete(s.states, hash)
}

func logSignals(path string, opts LogOptions, stdout, stderr io.Writer) (err error) {
	repo, err := githistory.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, repo.Close())
	}()
	local, err := newLocalDetectors(context.Background(), repo)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, local.Close())
	}()

	uri, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cache := newBlobCache(repo.Repository())
	stats := newScanStats(cache)
	walk, states, err := planCommitWalk(repo, opts)
	if err != nil {
		return err
	}
	snapshots, err := newSnapshotCollector(repo, local, "file://"+uri, opts, cache, stats)
	if err != nil {
		return err
	}
	if err := snapshots.writeStart(stdout, opts.JSONL); err != nil {
		return err
	}
	err = repo.WalkCommits(walk, func(commit githistory.Commit) error {
		forceFull := len(commit.Object.ParentHashes) == 0
		parent := emptyCommitState()
		var parentHash plumbing.Hash
		if len(commit.Object.ParentHashes) > 0 {
			parentHash = commit.Object.ParentHashes[0]
			var ok bool
			parent, ok = states.get(parentHash)
			if !ok {
				parentCommit, err := repo.Repository().CommitObject(parentHash)
				if err != nil {
					return err
				}
				parent, err = detectFullCommitState("file://"+uri, parentCommit, local, cache, stats)
				if err != nil {
					return err
				}
				states.retain(parentHash, parent)
				forceFull = true
			}
		}

		current, err := detectCommitState(
			"file://"+uri,
			commit.Object,
			parent,
			commit.Changes,
			forceFull,
			local,
			cache,
			stats,
		)
		if err != nil {
			return err
		}
		if !parentHash.IsZero() {
			states.release(parentHash)
		}
		states.retain(commit.Object.Hash, current)
		stats.commits++
		if opts.Progress > 0 && stats.commits%opts.Progress == 0 {
			if _, err := fmt.Fprintf(stderr, "signals: scanned %d commits\n", stats.commits); err != nil {
				return err
			}
		}
		if !dateInRange(commit.Object.Committer.When, opts.After, opts.Before) {
			return nil
		}

		var changes []signalChange
		var errorChanges []errorChange
		if len(commit.Object.ParentHashes) <= 1 {
			changes = diffSignals(parent.signals, current.signals)
			errorChanges = diffErrors(parent.errors, current.errors)
		}
		events := commitEvents(commit.Object)
		if err := writeCommitRecords(stdout, stderr, commit.Object, changes, errorChanges, events, opts.JSONL); err != nil {
			return err
		}
		return nil
	})
	if err == nil {
		err = snapshots.finish(stdout, opts.JSONL)
	}
	if opts.Stats {
		err = errors.Join(err, printStats(stderr, stats))
	}
	return err
}

func loadBoundarySnapshot(
	repo *git.Repository,
	local *localDetectors,
	uri, ref, boundary, date string,
	cache *blobCache,
	stats *scanStats,
) (boundarySnapshot, error) {
	snapshot := boundarySnapshot{
		boundary: boundary,
		date:     date,
		state:    emptyCommitState(),
	}
	commit, err := findFirstParentBefore(repo, ref, date)
	if err != nil {
		return boundarySnapshot{}, err
	}
	if commit == nil {
		return snapshot, nil
	}
	snapshot.commit = commit
	snapshot.state, err = detectFullCommitState(uri, commit, local, cache, stats)
	if err != nil {
		return boundarySnapshot{}, err
	}
	return snapshot, nil
}

func findFirstParentBefore(repo *git.Repository, ref, before string) (*object.Commit, error) {
	boundary, err := time.Parse(time.DateOnly, before)
	if err != nil {
		return nil, err
	}
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, err
	}
	for {
		if commit.Committer.When.Before(boundary) {
			return commit, nil
		}
		if len(commit.ParentHashes) == 0 {
			return nil, nil
		}
		commit, err = repo.CommitObject(commit.ParentHashes[0])
		if err != nil {
			return nil, err
		}
	}
}

func writeBoundarySnapshot(writer io.Writer, snapshot boundarySnapshot, jsonl bool) error {
	signals := make([]Signal, 0, len(snapshot.state.signals))
	for _, signal := range snapshot.state.signals {
		signals = append(signals, signal)
	}
	sortSignals(signals)
	errors := diffErrors(nil, snapshot.state.errors)

	if jsonl {
		record := jsonlSnapshotRecord{
			Type:            "snapshot",
			Boundary:        snapshot.boundary,
			Date:            snapshot.date,
			Signals:         make([]jsonlSignal, 0, len(signals)),
			Metrics:         snapshot.metrics,
			HistoryComplete: snapshot.historyComplete,
			MailmapOID:      snapshot.mailmapOID,
			Errors:          errors,
		}
		if snapshot.commit != nil {
			author := jsonlAuthor{Name: snapshot.commit.Author.Name, Email: snapshot.commit.Author.Email}
			committer := jsonlAuthor{Name: snapshot.commit.Committer.Name, Email: snapshot.commit.Committer.Email}
			authoredAt := snapshot.commit.Author.When
			committedAt := snapshot.commit.Committer.When
			record.Commit = snapshot.commit.Hash.String()
			record.Author = &author
			record.Committer = &committer
			record.AuthoredAt = &authoredAt
			record.CommittedAt = &committedAt
			record.Subject = githistory.CommitSubject(snapshot.commit.Message)
		}
		for _, signal := range signals {
			record.Signals = append(record.Signals, jsonSignal(signal))
		}
		return json.NewEncoder(writer).Encode(record)
	}

	if snapshot.commit == nil {
		if _, err := fmt.Fprintf(writer, "snapshot %s %s  before repository history\n", snapshot.boundary, snapshot.date); err != nil {
			return err
		}
		for _, metric := range snapshot.metrics {
			if _, err := fmt.Fprintf(writer, "  # %s\n", formatMetric(metric)); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer, "snapshot %s %s  %s  %s  %s\n",
		snapshot.boundary,
		snapshot.date,
		snapshot.commit.Hash.String()[:12],
		snapshot.commit.Committer.When.UTC().Format(time.DateOnly),
		githistory.CommitSubject(snapshot.commit.Message),
	); err != nil {
		return err
	}
	for _, signal := range signals {
		if _, err := fmt.Fprintf(writer, "  = %s\n", formatSignal(signal)); err != nil {
			return err
		}
	}
	for _, metric := range snapshot.metrics {
		if _, err := fmt.Fprintf(writer, "  # %s\n", formatMetric(metric)); err != nil {
			return err
		}
	}
	for _, detectorError := range errors {
		if _, err := fmt.Fprintf(writer, "  ! %s: %s\n", detectorError.Check, detectorError.Message); err != nil {
			return err
		}
	}
	return nil
}

func dateInRange(date time.Time, after, before string) bool {
	if after != "" {
		boundary, _ := time.Parse(time.DateOnly, after)
		if date.Before(boundary) {
			return false
		}
	}
	if before != "" {
		boundary, _ := time.Parse(time.DateOnly, before)
		if !date.Before(boundary) {
			return false
		}
	}
	return true
}

func writeCommitRecords(
	stdout, stderr io.Writer,
	commit *object.Commit,
	changes []signalChange,
	errorChanges []errorChange,
	events []jsonlSignal,
	jsonl bool,
) error {
	if len(changes) == 0 && len(errorChanges) == 0 && len(events) == 0 {
		return nil
	}
	if jsonl {
		if len(changes) > 0 || len(errorChanges) > 0 {
			if err := writeJSONLRecord(stdout, commit, changes, errorChanges); err != nil {
				return err
			}
		}
		if len(events) > 0 {
			if err := writeJSONLEventRecord(stdout, commit, events); err != nil {
				return err
			}
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "%s  %s  %s\n",
			commit.Hash.String()[:12],
			commit.Committer.When.UTC().Format(time.DateOnly),
			githistory.CommitSubject(commit.Message),
		); err != nil {
			return err
		}
		for _, change := range changes {
			if _, err := fmt.Fprintf(stdout, "  %c %s\n", change.Marker, formatSignal(change.Signal)); err != nil {
				return err
			}
		}
		for _, event := range events {
			if _, err := fmt.Fprintf(stdout, "  * %s\n", formatSignal(Signal(event))); err != nil {
				return err
			}
		}
	}
	for _, change := range errorChanges {
		if _, err := fmt.Fprintf(stderr, "%s  %s: %s\n", commit.Hash.String()[:12], change.Check, change.Message); err != nil {
			return err
		}
	}
	return nil
}

func writeJSONLRecord(writer io.Writer, commit *object.Commit, changes []signalChange, errors []errorChange) error {
	record := jsonlRecord{
		Type:        "change",
		Commit:      commit.Hash.String(),
		Author:      jsonlAuthor{Name: commit.Author.Name, Email: commit.Author.Email},
		Committer:   jsonlAuthor{Name: commit.Committer.Name, Email: commit.Committer.Email},
		AuthoredAt:  commit.Author.When,
		CommittedAt: commit.Committer.When,
		Subject:     githistory.CommitSubject(commit.Message),
		Changes:     make([]jsonlChange, 0, len(changes)),
		Errors:      errors,
	}
	for _, change := range changes {
		record.Changes = append(record.Changes, jsonlChange{
			Change: changeName(change.Marker),
			Check:  change.Signal.Check,
			Kind:   change.Signal.Kind,
			Name:   change.Signal.Name,
			Value:  change.Signal.Value,
			Path:   change.Signal.Path,
			Line:   change.Signal.Line,
		})
	}
	return json.NewEncoder(writer).Encode(record)
}

func jsonSignal(signal Signal) jsonlSignal {
	return jsonlSignal(signal)
}

func changeName(marker byte) string {
	if marker == '+' {
		return "added"
	}
	return "removed"
}

func detectFullCommitState(
	uri string,
	commit *object.Commit,
	local *localDetectors,
	cache *blobCache,
	stats *scanStats,
) (commitState, error) {
	return detectCommitState(uri, commit, emptyCommitState(), nil, true, local, cache, stats)
}

func detectCommitState(
	uri string,
	commit *object.Commit,
	parent commitState,
	changes []githistory.Change,
	forceFull bool,
	local *localDetectors,
	cache *blobCache,
	stats *scanStats,
) (commitState, error) {
	current := cloneCommitState(parent)
	languageStarted := time.Now()
	languages, err := languageInventoryForCommit(parent.languages, commit, changes, forceFull, cache)
	stats.languages += time.Since(languageStarted)
	if err != nil {
		return commitState{}, err
	}
	current.languages = languages
	programmingLanguages := current.languages.scorecard()
	languagesChanged := !parent.languages.sameLanguages(current.languages)
	paths := changedPaths(changes)
	var fullClient *commitClient

	for _, detector := range scorecardDetectors {
		detectorStats := stats.detectors[detector.name]
		scope := detector.scope(paths, forceFull)
		if detector.name == checkFuzzing && languagesChanged {
			scope = detectionScope{impact: impactFull}
		}
		if _, failed := parent.errors[detector.name]; failed && scope.impact != impactNone {
			scope = detectionScope{impact: impactFull}
		}
		if scope.impact == impactNone {
			detectorStats.skipped++
			continue
		}

		var client *commitClient
		var err error
		include := includeForDetector(detector, cache)
		switch scope.impact {
		case impactFull:
			detectorStats.full++
			if include != nil {
				client, err = newCommitClient(uri, commit, cache, nil, include, programmingLanguages)
			} else {
				if fullClient == nil {
					fullClient, err = newCommitClient(uri, commit, cache, nil, nil, programmingLanguages)
				}
				client = fullClient
			}
		case impactPartial:
			detectorStats.partial++
			client, err = newCommitClient(uri, commit, cache, scope.paths, include, programmingLanguages)
		}
		if err != nil {
			return commitState{}, err
		}

		started := time.Now()
		signals, err := detector.detect(context.Background(), client)
		detectorStats.duration += time.Since(started)
		detectorStats.runs++
		if err != nil {
			current.errors[detector.name] = err.Error()
			continue
		}

		delete(current.errors, detector.name)
		if scope.impact == impactFull {
			removeCheckSignals(current.signals, detector.name)
		} else {
			removePathSignals(current.signals, detector.name, scope.paths)
		}
		for _, signal := range signals {
			current.signals[signalKey(signal)] = signal
		}
	}
	return local.detect(context.Background(), commit, current, changes, forceFull, languagesChanged, stats)
}

func includeForDetector(detector detector, cache *blobCache) func(string) bool {
	if detector.name == checkFuzzing {
		return cache.includeFuzzingPath
	}
	return detector.include
}

func emptyCommitState() commitState {
	return commitState{
		signals:    make(map[string]Signal),
		errors:     make(map[string]string),
		languages:  make(languageInventory),
		reuseFiles: make(map[string]reuseFile),
	}
}

func cloneCommitState(state commitState) commitState {
	clone := commitState{
		signals:        make(map[string]Signal, len(state.signals)),
		errors:         make(map[string]string, len(state.errors)),
		languages:      state.languages,
		briefLanguages: append([]string(nil), state.briefLanguages...),
		reuseFiles:     state.reuseFiles,
		reuseActive:    state.reuseActive,
	}
	for key, signal := range state.signals {
		clone.signals[key] = signal
	}
	for check, message := range state.errors {
		clone.errors[check] = message
	}
	return clone
}

func changedPaths(changes []githistory.Change) []string {
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		paths = append(paths, change.Path)
	}
	return paths
}

func removeCheckSignals(signals map[string]Signal, check string) {
	for key, signal := range signals {
		if signal.Check == check {
			delete(signals, key)
		}
	}
}

func removePathSignals(signals map[string]Signal, check string, paths map[string]bool) {
	for key, signal := range signals {
		if signal.Check == check && paths[signal.Path] {
			delete(signals, key)
		}
	}
}

func printStats(writer io.Writer, stats *scanStats) error {
	if _, err := fmt.Fprintf(writer, "signals: scanned %d commits in %s\n", stats.commits, time.Since(stats.started).Round(time.Millisecond)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "signals: blobs %d unique, %d reads, %d cache hits, %d bytes\n",
		len(stats.cache.data), stats.cache.requests, stats.cache.hits, stats.cache.bytes); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "signals: Languages paths=%d analyzed=%d time=%s\n",
		len(stats.cache.languagePaths),
		len(stats.cache.languageBlobs),
		stats.languages.Round(time.Millisecond),
	); err != nil {
		return err
	}
	for _, detector := range scorecardDetectors {
		result := stats.detectors[detector.name]
		if _, err := fmt.Fprintf(writer, "signals: %-24s runs=%d full=%d partial=%d skipped=%d time=%s\n",
			detector.name,
			result.runs,
			result.full,
			result.partial,
			result.skipped,
			result.duration.Round(time.Millisecond),
		); err != nil {
			return err
		}
	}
	for _, name := range localDetectorNames {
		result := stats.detectors[name]
		if _, err := fmt.Fprintf(writer, "signals: %-24s runs=%d full=%d partial=%d skipped=%d time=%s\n",
			name,
			result.runs,
			result.full,
			result.partial,
			result.skipped,
			result.duration.Round(time.Millisecond),
		); err != nil {
			return err
		}
	}
	return nil
}

func diffSignals(previous, current map[string]Signal) []signalChange {
	changes := make([]signalChange, 0)
	for key, signal := range previous {
		if _, ok := current[key]; !ok {
			changes = append(changes, signalChange{Marker: '-', Signal: signal})
		}
	}
	for key, signal := range current {
		if _, ok := previous[key]; !ok {
			changes = append(changes, signalChange{Marker: '+', Signal: signal})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Marker != changes[j].Marker {
			return changes[i].Marker < changes[j].Marker
		}
		return signalKey(changes[i].Signal) < signalKey(changes[j].Signal)
	})
	return changes
}

type errorChange struct {
	Check   string `json:"check"`
	Message string `json:"message"`
}

func diffErrors(previous, current map[string]string) []errorChange {
	var changes []errorChange
	for check, message := range current {
		if previous[check] != message {
			changes = append(changes, errorChange{Check: check, Message: message})
		}
	}
	for check := range previous {
		if _, ok := current[check]; !ok {
			changes = append(changes, errorChange{Check: check, Message: "detection recovered"})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Check < changes[j].Check })
	return changes
}

func formatSignal(signal Signal) string {
	var result strings.Builder
	result.WriteString(signal.Check)
	if signal.Kind != "" {
		result.WriteByte('/')
		result.WriteString(signal.Kind)
	}
	if signal.Name != "" {
		result.WriteByte(' ')
		result.WriteString(signal.Name)
	}
	if signal.Path != "" {
		result.WriteString(" at ")
		result.WriteString(signal.Path)
		if signal.Line > 0 {
			fmt.Fprintf(&result, ":%d", signal.Line)
		}
	}
	if signal.Value != "" {
		result.WriteString(" = ")
		result.WriteString(signal.Value)
	}
	return result.String()
}
