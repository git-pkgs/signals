package main

import (
	"context"
	"encoding/json"
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
	Type       string        `json:"type"`
	Commit     string        `json:"commit"`
	Author     jsonlAuthor   `json:"author"`
	AuthoredAt time.Time     `json:"authored_at"`
	Subject    string        `json:"subject"`
	Changes    []jsonlChange `json:"changes,omitempty"`
	Errors     []errorChange `json:"errors,omitempty"`
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
	Type       string        `json:"type"`
	Boundary   string        `json:"boundary"`
	Date       string        `json:"date"`
	Commit     string        `json:"commit,omitempty"`
	Author     *jsonlAuthor  `json:"author,omitempty"`
	AuthoredAt *time.Time    `json:"authored_at,omitempty"`
	Subject    string        `json:"subject,omitempty"`
	Signals    []jsonlSignal `json:"signals"`
	Errors     []errorChange `json:"errors,omitempty"`
}

type boundarySnapshot struct {
	boundary string
	date     string
	commit   *object.Commit
	state    commitState
}

type commitState struct {
	signals map[string]Signal
	errors  map[string]string
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
	return stats
}

func logSignals(path string, opts LogOptions, stdout, stderr io.Writer) error {
	repo, err := githistory.Open(path)
	if err != nil {
		return err
	}
	defer repo.Close()

	uri, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cache := newBlobCache()
	stats := newScanStats(cache)
	states := make(map[string]commitState)
	var startSnapshot, endSnapshot boundarySnapshot
	if opts.Snapshots {
		startSnapshot, err = loadBoundarySnapshot(repo.Repository(), "file://"+uri, opts.Ref, "start", opts.After, cache, stats)
		if err != nil {
			return err
		}
		endSnapshot, err = loadBoundarySnapshot(repo.Repository(), "file://"+uri, opts.Ref, "end", opts.Before, cache, stats)
		if err != nil {
			return err
		}
		if err := writeBoundarySnapshot(stdout, startSnapshot, opts.JSONL); err != nil {
			return err
		}
	}
	err = repo.WalkCommits(githistory.CommitOptions{
		Ref:     opts.Ref,
		Since:   opts.Since,
		Merges:  true,
		Workers: opts.Workers,
	}, func(commit githistory.Commit) error {
		parent := emptyCommitState()
		if len(commit.Object.ParentHashes) > 0 {
			parentHash := commit.Object.ParentHashes[0]
			var ok bool
			parent, ok = states[parentHash.String()]
			if !ok {
				parentCommit, err := repo.Repository().CommitObject(parentHash)
				if err != nil {
					return err
				}
				parent, err = detectFullCommitState("file://"+uri, parentCommit, cache, stats)
				if err != nil {
					return err
				}
				states[parentHash.String()] = parent
			}
		}

		current, err := detectCommitState(
			"file://"+uri,
			commit.Object,
			parent,
			commit.Changes,
			len(commit.Object.ParentHashes) == 0,
			cache,
			stats,
		)
		if err != nil {
			return err
		}
		states[commit.Object.Hash.String()] = current
		stats.commits++
		if opts.Progress > 0 && stats.commits%opts.Progress == 0 {
			fmt.Fprintf(stderr, "signals: scanned %d commits\n", stats.commits)
		}
		if len(commit.Object.ParentHashes) > 1 {
			return nil
		}
		if !dateInRange(commit.Object.Author.When, opts.After, opts.Before) {
			return nil
		}

		changes := diffSignals(parent.signals, current.signals)
		errorChanges := diffErrors(parent.errors, current.errors)
		if len(changes) > 0 || len(errorChanges) > 0 {
			if opts.JSONL {
				if err := writeJSONLRecord(stdout, commit.Object, changes, errorChanges); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(stdout, "%s  %s  %s\n",
					commit.Object.Hash.String()[:12],
					commit.Object.Author.When.Format(time.DateOnly),
					githistory.CommitSubject(commit.Object.Message),
				)
				for _, change := range changes {
					fmt.Fprintf(stdout, "  %c %s\n", change.Marker, formatSignal(change.Signal))
				}
			}
			for _, change := range errorChanges {
				fmt.Fprintf(stderr, "%s  %s: %s\n", commit.Object.Hash.String()[:12], change.Check, change.Message)
			}
		}
		return nil
	})
	if err == nil && opts.Snapshots {
		if writeErr := writeBoundarySnapshot(stdout, endSnapshot, opts.JSONL); writeErr != nil {
			err = writeErr
		}
	}
	if opts.Stats {
		printStats(stderr, stats)
	}
	return err
}

func loadBoundarySnapshot(
	repo *git.Repository,
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
	snapshot.state, err = detectFullCommitState(uri, commit, cache, stats)
	if err != nil {
		return boundarySnapshot{}, err
	}
	return snapshot, nil
}

func findFirstParentBefore(repo *git.Repository, ref, before string) (*object.Commit, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, err
	}
	var candidate *object.Commit
	for {
		if commit.Author.When.Format(time.DateOnly) < before &&
			(candidate == nil || commit.Author.When.After(candidate.Author.When)) {
			candidate = commit
		}
		if len(commit.ParentHashes) == 0 {
			return candidate, nil
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
			Type:     "snapshot",
			Boundary: snapshot.boundary,
			Date:     snapshot.date,
			Signals:  make([]jsonlSignal, 0, len(signals)),
			Errors:   errors,
		}
		if snapshot.commit != nil {
			author := jsonlAuthor{Name: snapshot.commit.Author.Name, Email: snapshot.commit.Author.Email}
			authoredAt := snapshot.commit.Author.When
			record.Commit = snapshot.commit.Hash.String()
			record.Author = &author
			record.AuthoredAt = &authoredAt
			record.Subject = githistory.CommitSubject(snapshot.commit.Message)
		}
		for _, signal := range signals {
			record.Signals = append(record.Signals, jsonSignal(signal))
		}
		return json.NewEncoder(writer).Encode(record)
	}

	if snapshot.commit == nil {
		_, err := fmt.Fprintf(writer, "snapshot %s %s  before repository history\n", snapshot.boundary, snapshot.date)
		return err
	}
	if _, err := fmt.Fprintf(writer, "snapshot %s %s  %s  %s  %s\n",
		snapshot.boundary,
		snapshot.date,
		snapshot.commit.Hash.String()[:12],
		snapshot.commit.Author.When.Format(time.DateOnly),
		githistory.CommitSubject(snapshot.commit.Message),
	); err != nil {
		return err
	}
	for _, signal := range signals {
		if _, err := fmt.Fprintf(writer, "  = %s\n", formatSignal(signal)); err != nil {
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
	value := date.Format(time.DateOnly)
	return (after == "" || value >= after) && (before == "" || value < before)
}

func writeJSONLRecord(writer io.Writer, commit *object.Commit, changes []signalChange, errors []errorChange) error {
	record := jsonlRecord{
		Type:       "change",
		Commit:     commit.Hash.String(),
		Author:     jsonlAuthor{Name: commit.Author.Name, Email: commit.Author.Email},
		AuthoredAt: commit.Author.When,
		Subject:    githistory.CommitSubject(commit.Message),
		Changes:    make([]jsonlChange, 0, len(changes)),
		Errors:     errors,
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
	return jsonlSignal{
		Check: signal.Check,
		Kind:  signal.Kind,
		Name:  signal.Name,
		Value: signal.Value,
		Path:  signal.Path,
		Line:  signal.Line,
	}
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
	cache *blobCache,
	stats *scanStats,
) (commitState, error) {
	return detectCommitState(uri, commit, emptyCommitState(), nil, true, cache, stats)
}

func detectCommitState(
	uri string,
	commit *object.Commit,
	parent commitState,
	changes []githistory.Change,
	forceFull bool,
	cache *blobCache,
	stats *scanStats,
) (commitState, error) {
	current := cloneCommitState(parent)
	paths := changedPaths(changes)
	var fullClient *commitClient

	for _, detector := range scorecardDetectors {
		detectorStats := stats.detectors[detector.name]
		scope := detector.scope(paths, forceFull)
		if _, failed := parent.errors[detector.name]; failed && scope.impact != impactNone {
			scope = detectionScope{impact: impactFull}
		}
		if scope.impact == impactNone {
			detectorStats.skipped++
			continue
		}

		var client *commitClient
		var err error
		switch scope.impact {
		case impactFull:
			detectorStats.full++
			if fullClient == nil {
				fullClient, err = newCommitClient(uri, commit, cache, nil)
			}
			client = fullClient
		case impactPartial:
			detectorStats.partial++
			client, err = newCommitClient(uri, commit, cache, scope.paths)
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
	return current, nil
}

func emptyCommitState() commitState {
	return commitState{
		signals: make(map[string]Signal),
		errors:  make(map[string]string),
	}
}

func cloneCommitState(state commitState) commitState {
	clone := commitState{
		signals: make(map[string]Signal, len(state.signals)),
		errors:  make(map[string]string, len(state.errors)),
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

func printStats(writer io.Writer, stats *scanStats) {
	fmt.Fprintf(writer, "signals: scanned %d commits in %s\n", stats.commits, time.Since(stats.started).Round(time.Millisecond))
	fmt.Fprintf(writer, "signals: blobs %d unique, %d reads, %d cache hits, %d bytes\n",
		len(stats.cache.data), stats.cache.requests, stats.cache.hits, stats.cache.bytes)
	for _, detector := range scorecardDetectors {
		result := stats.detectors[detector.name]
		fmt.Fprintf(writer, "signals: %-24s runs=%d full=%d partial=%d skipped=%d time=%s\n",
			detector.name,
			result.runs,
			result.full,
			result.partial,
			result.skipped,
			result.duration.Round(time.Millisecond),
		)
	}
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
