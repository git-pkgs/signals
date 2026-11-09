package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	githistory "github.com/git-pkgs/history"
	"github.com/go-git/go-git/v6/plumbing/object"
)

type stateOutputFormat int

const (
	stateOutputHuman stateOutputFormat = iota
	stateOutputMarkdown
	stateOutputJSON
	stateDiffRefCount = 2
)

type revisionRecord struct {
	Revision    string      `json:"revision"`
	Commit      string      `json:"commit"`
	Author      jsonlAuthor `json:"author"`
	Committer   jsonlAuthor `json:"committer"`
	AuthoredAt  time.Time   `json:"authored_at"`
	CommittedAt time.Time   `json:"committed_at"`
	Subject     string      `json:"subject"`
}

type stateSummaryRecord struct {
	Type       string `json:"type"`
	Repository string `json:"repository"`
	revisionRecord
	SignalCount int           `json:"signal_count"`
	CheckCount  int           `json:"check_count"`
	Signals     []jsonlSignal `json:"signals"`
	Events      []jsonlSignal `json:"events,omitempty"`
	Errors      []errorChange `json:"errors,omitempty"`
}

type stateDiffRecord struct {
	Type       string         `json:"type"`
	Repository string         `json:"repository"`
	From       revisionRecord `json:"from"`
	To         revisionRecord `json:"to"`
	Changes    []jsonlChange  `json:"changes"`
	FromErrors []errorChange  `json:"from_errors,omitempty"`
	ToErrors   []errorChange  `json:"to_errors,omitempty"`
}

type detectedRevision struct {
	revision string
	commit   *object.Commit
	signals  []Signal
	events   []jsonlSignal
	errors   []errorChange
}

type stateScanner struct {
	repo  *githistory.Repo
	local *localDetectors
	cache *blobCache
	stats *scanStats
}

func runSummary(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("summary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ref := flags.String("ref", "HEAD", "revision to summarize")
	human := flags.Bool("human", false, "write human-readable text")
	markdown := flags.Bool("markdown", false, "write Markdown")
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	format, err := selectStateOutputFormat(*human, *markdown, *jsonOutput)
	if err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("usage: signals summary [options] [repo]")
	}
	repo := "."
	if flags.NArg() == 1 {
		repo = flags.Arg(0)
	}
	return summarizeState(repo, *ref, format, stdout)
}

func runStateDiff(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	human := flags.Bool("human", false, "write human-readable text")
	markdown := flags.Bool("markdown", false, "write Markdown")
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	format, err := selectStateOutputFormat(*human, *markdown, *jsonOutput)
	if err != nil {
		return err
	}
	if flags.NArg() < stateDiffRefCount || flags.NArg() > stateDiffRefCount+1 {
		return errors.New("usage: signals diff [options] <ref1> <ref2> [repo]")
	}
	repo := "."
	if flags.NArg() == stateDiffRefCount+1 {
		repo = flags.Arg(stateDiffRefCount)
	}
	return diffStates(repo, flags.Arg(0), flags.Arg(1), format, stdout)
}

func selectStateOutputFormat(human, markdown, jsonOutput bool) (stateOutputFormat, error) {
	selected := 0
	for _, enabled := range []bool{human, markdown, jsonOutput} {
		if enabled {
			selected++
		}
	}
	if selected > 1 {
		return stateOutputHuman, errors.New("choose only one of --human, --markdown, and --json")
	}
	if markdown {
		return stateOutputMarkdown, nil
	}
	if jsonOutput {
		return stateOutputJSON, nil
	}
	return stateOutputHuman, nil
}

func summarizeState(path, revision string, format stateOutputFormat, writer io.Writer) (err error) {
	scanner, err := openStateScanner(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, scanner.close())
	}()
	detected, err := scanner.detect(revision, true)
	if err != nil {
		return err
	}
	switch format {
	case stateOutputMarkdown:
		return writeSummaryMarkdown(writer, path, detected)
	case stateOutputJSON:
		return writeSummaryJSON(writer, path, detected)
	default:
		return writeSummaryHuman(writer, path, detected)
	}
}

func diffStates(path, fromRevision, toRevision string, format stateOutputFormat, writer io.Writer) (err error) {
	scanner, err := openStateScanner(path)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, scanner.close())
	}()
	from, err := scanner.detect(fromRevision, false)
	if err != nil {
		return err
	}
	to, err := scanner.detect(toRevision, false)
	if err != nil {
		return err
	}
	changes := diffSignals(stateSignalMap(from.signals), stateSignalMap(to.signals))
	switch format {
	case stateOutputMarkdown:
		return writeDiffMarkdown(writer, path, from, to, changes)
	case stateOutputJSON:
		return writeDiffJSON(writer, path, from, to, changes)
	default:
		return writeDiffHuman(writer, path, from, to, changes)
	}
}

func openStateScanner(path string) (*stateScanner, error) {
	repo, err := githistory.Open(path)
	if err != nil {
		return nil, err
	}
	local, err := newLocalDetectors(context.Background(), repo)
	if err != nil {
		return nil, errors.Join(err, repo.Close())
	}
	cache := newBlobCache(repo.Repository())
	return &stateScanner{
		repo:  repo,
		local: local,
		cache: cache,
		stats: newScanStats(cache),
	}, nil
}

func (s *stateScanner) close() error {
	return errors.Join(s.local.Close(), s.repo.Close())
}

func (s *stateScanner) detect(revision string, includeEvents bool) (detectedRevision, error) {
	hash, err := resolveRevision(s.repo.Repository(), revision)
	if err != nil {
		return detectedRevision{}, err
	}
	commit, err := s.repo.Repository().CommitObject(hash)
	if err != nil {
		return detectedRevision{}, err
	}
	state, err := detectFullCommitState(commit, s.local, s.cache, s.stats)
	if err != nil {
		return detectedRevision{}, err
	}
	signals := make([]Signal, 0, len(state.signals))
	for _, signal := range state.signals {
		signals = append(signals, signal)
	}
	sortSignals(signals)
	detected := detectedRevision{
		revision: revision,
		commit:   commit,
		signals:  signals,
		errors:   diffErrors(nil, state.errors),
	}
	if !includeEvents {
		return detected, nil
	}
	repository, err := repositoryEvents(s.repo.Repository(), revision)
	if err != nil {
		return detectedRevision{}, err
	}
	detected.events = append(commitEvents(commit), repository[commit.Hash]...)
	sortEventSignals(detected.events)
	return detected, nil
}

func stateSignalMap(signals []Signal) map[string]Signal {
	result := make(map[string]Signal, len(signals))
	for _, signal := range signals {
		result[signalKey(signal)] = signal
	}
	return result
}

func revisionRecordFor(detected detectedRevision) revisionRecord {
	return revisionRecord{
		Revision:    detected.revision,
		Commit:      detected.commit.Hash.String(),
		Author:      jsonlAuthor{Name: detected.commit.Author.Name, Email: detected.commit.Author.Email},
		Committer:   jsonlAuthor{Name: detected.commit.Committer.Name, Email: detected.commit.Committer.Email},
		AuthoredAt:  detected.commit.Author.When,
		CommittedAt: detected.commit.Committer.When,
		Subject:     githistory.CommitSubject(detected.commit.Message),
	}
}

func writeSummaryJSON(writer io.Writer, path string, detected detectedRevision) error {
	record := stateSummaryRecord{
		Type:           "summary",
		Repository:     filepath.Clean(path),
		revisionRecord: revisionRecordFor(detected),
		SignalCount:    len(detected.signals),
		CheckCount:     signalCheckCount(detected.signals),
		Signals:        jsonSignals(detected.signals),
		Events:         detected.events,
		Errors:         detected.errors,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(record)
}

func writeDiffJSON(
	writer io.Writer,
	path string,
	from, to detectedRevision,
	changes []signalChange,
) error {
	record := stateDiffRecord{
		Type:       "diff",
		Repository: filepath.Clean(path),
		From:       revisionRecordFor(from),
		To:         revisionRecordFor(to),
		Changes:    jsonChanges(changes),
		FromErrors: from.errors,
		ToErrors:   to.errors,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(record)
}

func jsonSignals(signals []Signal) []jsonlSignal {
	result := make([]jsonlSignal, 0, len(signals))
	for _, signal := range signals {
		result = append(result, jsonSignal(signal))
	}
	return result
}

func jsonChanges(changes []signalChange) []jsonlChange {
	result := make([]jsonlChange, 0, len(changes))
	for _, change := range changes {
		result = append(result, jsonlChange{
			Change: changeName(change.Marker),
			Check:  change.Signal.Check,
			Kind:   change.Signal.Kind,
			Name:   change.Signal.Name,
			Value:  change.Signal.Value,
			Path:   change.Signal.Path,
			Line:   change.Signal.Line,
		})
	}
	return result
}

func signalCheckCount(signals []Signal) int {
	checks := make(map[string]bool)
	for _, signal := range signals {
		checks[signal.Check] = true
	}
	return len(checks)
}

func writeSummaryHuman(writer io.Writer, path string, detected detectedRevision) error {
	var output strings.Builder
	fmt.Fprintf(&output, "Security signals for %s\n", filepath.Clean(path))
	writeRevisionHuman(&output, detected)
	fmt.Fprintf(&output, "Signals:     %d across %d checks\n", len(detected.signals), signalCheckCount(detected.signals))
	for _, signal := range detected.signals {
		fmt.Fprintf(&output, "  = %s\n", stateText(formatSignal(signal)))
	}
	if len(detected.events) > 0 {
		fmt.Fprintf(&output, "Events:      %d\n", len(detected.events))
		for _, event := range detected.events {
			fmt.Fprintf(&output, "  @ %s\n", stateText(formatSignal(Signal(event))))
		}
	}
	writeErrorsHuman(&output, "Errors", detected.errors)
	_, err := io.WriteString(writer, output.String())
	return err
}

func writeDiffHuman(
	writer io.Writer,
	path string,
	from, to detectedRevision,
	changes []signalChange,
) error {
	var output strings.Builder
	fmt.Fprintf(&output, "Security signal diff for %s\n", filepath.Clean(path))
	fmt.Fprintf(&output, "From:        %s  %s  %s\n", from.revision, from.commit.Hash.String(), stateText(githistory.CommitSubject(from.commit.Message)))
	fmt.Fprintf(&output, "To:          %s  %s  %s\n", to.revision, to.commit.Hash.String(), stateText(githistory.CommitSubject(to.commit.Message)))
	fmt.Fprintf(&output, "Changes:     %d\n", len(changes))
	for _, change := range changes {
		fmt.Fprintf(&output, "  %c %s\n", change.Marker, stateText(formatSignal(change.Signal)))
	}
	writeErrorsHuman(&output, "From errors", from.errors)
	writeErrorsHuman(&output, "To errors", to.errors)
	_, err := io.WriteString(writer, output.String())
	return err
}

func writeRevisionHuman(output *strings.Builder, detected detectedRevision) {
	fmt.Fprintf(output, "Revision:    %s\n", stateText(detected.revision))
	fmt.Fprintf(output, "Commit:      %s\n", detected.commit.Hash)
	fmt.Fprintf(output, "Author:      %s <%s>\n", stateText(detected.commit.Author.Name), stateText(detected.commit.Author.Email))
	fmt.Fprintf(output, "Committed:   %s\n", detected.commit.Committer.When.UTC().Format(time.RFC3339))
	fmt.Fprintf(output, "Subject:     %s\n", stateText(githistory.CommitSubject(detected.commit.Message)))
}

func writeErrorsHuman(output *strings.Builder, label string, detectedErrors []errorChange) {
	if len(detectedErrors) == 0 {
		return
	}
	fmt.Fprintf(output, "%s: %d\n", label, len(detectedErrors))
	for _, detectedError := range detectedErrors {
		fmt.Fprintf(output, "  ! %s: %s\n", stateText(detectedError.Check), stateText(detectedError.Message))
	}
}

func stateText(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\r", "\\r", "\n", "\\n", "\t", "\\t").Replace(value)
}

func writeSummaryMarkdown(writer io.Writer, path string, detected detectedRevision) error {
	var output strings.Builder
	fmt.Fprintf(&output, "# Security signals for %s\n\n", markdownCell(filepath.Clean(path)))
	writeRevisionMarkdown(&output, detected)
	fmt.Fprintf(&output, "\n%d signals across %d checks.\n", len(detected.signals), signalCheckCount(detected.signals))
	writeSignalsMarkdown(&output, "Signals", detected.signals)
	writeEventsMarkdown(&output, detected.events)
	writeErrorsMarkdown(&output, "Errors", detected.errors)
	_, err := io.WriteString(writer, output.String())
	return err
}

func writeDiffMarkdown(
	writer io.Writer,
	path string,
	from, to detectedRevision,
	changes []signalChange,
) error {
	var output strings.Builder
	fmt.Fprintf(&output, "# Security signal diff for %s\n\n", markdownCell(filepath.Clean(path)))
	output.WriteString("| | Revision | Commit | Committed | Subject |\n")
	output.WriteString("| --- | --- | --- | --- | --- |\n")
	writeDiffRevisionMarkdown(&output, "From", from)
	writeDiffRevisionMarkdown(&output, "To", to)
	output.WriteString("\n## Changes\n\n")
	if len(changes) == 0 {
		output.WriteString("No signal changes detected.\n")
	} else {
		output.WriteString("| Change | Check | Kind | Name | Value | Location |\n")
		output.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		for _, change := range changes {
			writeMarkdownChangeRow(&output, change)
		}
	}
	writeErrorsMarkdown(&output, "From errors", from.errors)
	writeErrorsMarkdown(&output, "To errors", to.errors)
	_, err := io.WriteString(writer, output.String())
	return err
}

func writeRevisionMarkdown(output *strings.Builder, detected detectedRevision) {
	output.WriteString("| Field | Value |\n")
	output.WriteString("| --- | --- |\n")
	fmt.Fprintf(output, "| Revision | %s |\n", markdownCell(detected.revision))
	fmt.Fprintf(output, "| Commit | %s |\n", detected.commit.Hash)
	fmt.Fprintf(output, "| Author | %s &lt;%s&gt; |\n", markdownCell(detected.commit.Author.Name), markdownCell(detected.commit.Author.Email))
	fmt.Fprintf(output, "| Committed | %s |\n", detected.commit.Committer.When.UTC().Format(time.RFC3339))
	fmt.Fprintf(output, "| Subject | %s |\n", markdownCell(githistory.CommitSubject(detected.commit.Message)))
}

func writeDiffRevisionMarkdown(output *strings.Builder, label string, detected detectedRevision) {
	fmt.Fprintf(output, "| %s | %s | %s | %s | %s |\n",
		label,
		markdownCell(detected.revision),
		detected.commit.Hash,
		detected.commit.Committer.When.UTC().Format(time.RFC3339),
		markdownCell(githistory.CommitSubject(detected.commit.Message)),
	)
}

func writeSignalsMarkdown(output *strings.Builder, heading string, signals []Signal) {
	fmt.Fprintf(output, "\n## %s\n\n", heading)
	if len(signals) == 0 {
		output.WriteString("No signals detected.\n")
		return
	}
	output.WriteString("| Check | Kind | Name | Value | Location |\n")
	output.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, signal := range signals {
		writeMarkdownSignalRow(output, signal.Check, signal)
	}
}

func writeEventsMarkdown(output *strings.Builder, events []jsonlSignal) {
	if len(events) == 0 {
		return
	}
	output.WriteString("\n## Events\n\n")
	output.WriteString("| Check | Kind | Name | Value | Location |\n")
	output.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, event := range events {
		writeMarkdownSignalRow(output, event.Check, Signal(event))
	}
}

func writeMarkdownSignalRow(output *strings.Builder, first string, signal Signal) {
	fmt.Fprintf(output, "| %s | %s | %s | %s | %s |\n",
		markdownCell(first),
		markdownCell(signal.Kind),
		markdownCell(signal.Name),
		markdownCell(signal.Value),
		markdownCell(signalLocation(signal)),
	)
}

func writeMarkdownChangeRow(output *strings.Builder, change signalChange) {
	fmt.Fprintf(output, "| %s | %s | %s | %s | %s | %s |\n",
		changeName(change.Marker),
		markdownCell(change.Signal.Check),
		markdownCell(change.Signal.Kind),
		markdownCell(change.Signal.Name),
		markdownCell(change.Signal.Value),
		markdownCell(signalLocation(change.Signal)),
	)
}

func writeErrorsMarkdown(output *strings.Builder, heading string, detectedErrors []errorChange) {
	if len(detectedErrors) == 0 {
		return
	}
	fmt.Fprintf(output, "\n## %s\n\n", heading)
	output.WriteString("| Detector | Error |\n")
	output.WriteString("| --- | --- |\n")
	for _, detectedError := range detectedErrors {
		fmt.Fprintf(output, "| %s | %s |\n", markdownCell(detectedError.Check), markdownCell(detectedError.Message))
	}
}

func signalLocation(signal Signal) string {
	if signal.Path == "" {
		return ""
	}
	if signal.Line == 0 {
		return signal.Path
	}
	return fmt.Sprintf("%s:%d", signal.Path, signal.Line)
}

func markdownCell(value string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"|", "&#124;",
		"\r\n", "<br>",
		"\r", "<br>",
		"\n", "<br>",
	).Replace(value)
}
