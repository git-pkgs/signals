package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

const (
	checkGittuf        = "Gittuf"
	checkSignedRelease = "Signed-Release"
	gittufPolicyRef    = "refs/gittuf/policy"
	gittufRSLRef       = "refs/gittuf/reference-state-log"
	gittufAttestRef    = "refs/gittuf/attestations"
)

func repositoryEvents(repo *git.Repository, selectedRef string) (map[plumbing.Hash][]jsonlSignal, error) {
	events := make(map[plumbing.Hash][]jsonlSignal)
	if err := addSignedTagEvents(repo, events); err != nil {
		return nil, err
	}
	if err := addGittufEvents(repo, selectedRef, events); err != nil {
		return nil, err
	}
	for hash := range events {
		sortEventSignals(events[hash])
	}
	return events, nil
}

func addSignedTagEvents(repo *git.Repository, events map[plumbing.Hash][]jsonlSignal) error {
	refs, err := repo.Tags()
	if err != nil {
		return err
	}
	defer refs.Close()
	for {
		ref, err := refs.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		tag, err := repo.TagObject(ref.Hash())
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			if err := addTaggedCommitEvent(repo, ref, events); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("read tag %s: %w", ref.Name(), err)
		}
		target, ok, err := resolveCommit(repo, tag.Target)
		if err != nil {
			return fmt.Errorf("resolve tag %s: %w", ref.Name(), err)
		}
		if !ok {
			continue
		}
		name := strings.TrimPrefix(ref.Name().String(), "refs/tags/")
		signature := tag.Signature + tag.SignatureSHA256
		if signature != "" {
			events[target] = append(events[target], jsonlSignal{
				Check: checkSignedRelease,
				Kind:  "tag-" + signatureKind(signature),
				Name:  name,
				Value: tag.Hash.String(),
			})
		}
		if err := addTaggedCommitEventAt(repo, target, name, events); err != nil {
			return err
		}
	}
}

func addTaggedCommitEvent(
	repo *git.Repository,
	ref *plumbing.Reference,
	events map[plumbing.Hash][]jsonlSignal,
) error {
	target, ok, err := resolveCommit(repo, ref.Hash())
	if err != nil || !ok {
		return err
	}
	return addTaggedCommitEventAt(
		repo,
		target,
		strings.TrimPrefix(ref.Name().String(), "refs/tags/"),
		events,
	)
}

func addTaggedCommitEventAt(
	repo *git.Repository,
	target plumbing.Hash,
	name string,
	events map[plumbing.Hash][]jsonlSignal,
) error {
	commit, err := repo.CommitObject(target)
	if err != nil {
		return err
	}
	signature := commit.Signature + commit.SignatureSHA256
	if signature == "" {
		return nil
	}
	events[target] = append(events[target], jsonlSignal{
		Check: checkSignedRelease,
		Kind:  "commit-" + signatureKind(signature),
		Name:  name,
	})
	return nil
}

func addGittufEvents(
	repo *git.Repository,
	selectedRef string,
	events map[plumbing.Hash][]jsonlSignal,
) error {
	tip, err := resolveRevision(repo, selectedRef)
	if err != nil {
		return err
	}
	for _, candidate := range []struct {
		name string
		kind string
	}{
		{name: gittufPolicyRef, kind: "policy-ref"},
		{name: gittufAttestRef, kind: "attestations-ref"},
	} {
		ref, err := repo.Reference(plumbing.ReferenceName(candidate.name), true)
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		events[tip] = append(events[tip], jsonlSignal{
			Check: checkGittuf,
			Kind:  candidate.kind,
			Name:  candidate.name,
			Value: ref.Hash().String(),
		})
	}
	rsl, err := repo.Reference(plumbing.ReferenceName(gittufRSLRef), true)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	count, err := firstParentCount(repo, rsl.Hash())
	if err != nil {
		return fmt.Errorf("count %s: %w", gittufRSLRef, err)
	}
	events[tip] = append(events[tip],
		jsonlSignal{Check: checkGittuf, Kind: "rsl-ref", Name: gittufRSLRef, Value: rsl.Hash().String()},
		jsonlSignal{Check: checkGittuf, Kind: "rsl-entry-count", Value: strconv.Itoa(count)},
	)
	return nil
}

func resolveRevision(repo *git.Repository, revision string) (plumbing.Hash, error) {
	var hash plumbing.Hash
	if revision == "" {
		ref, err := repo.Head()
		if err != nil {
			return plumbing.ZeroHash, err
		}
		hash = ref.Hash()
	} else {
		resolved, err := repo.ResolveRevision(plumbing.Revision(revision))
		if err != nil {
			return plumbing.ZeroHash, err
		}
		hash = *resolved
	}
	commit, ok, err := resolveCommit(repo, hash)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if !ok {
		return plumbing.ZeroHash, fmt.Errorf("revision %q does not resolve to a commit", revision)
	}
	return commit, nil
}

func resolveCommit(repo *git.Repository, hash plumbing.Hash) (plumbing.Hash, bool, error) {
	seen := make(map[plumbing.Hash]bool)
	for {
		if seen[hash] {
			return plumbing.ZeroHash, false, fmt.Errorf("cyclic tag at %s", hash)
		}
		seen[hash] = true
		obj, err := repo.Object(plumbing.AnyObject, hash)
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		switch value := obj.(type) {
		case *object.Commit:
			return value.Hash, true, nil
		case *object.Tag:
			hash = value.Target
		default:
			return plumbing.ZeroHash, false, nil
		}
	}
}

func firstParentCount(repo *git.Repository, hash plumbing.Hash) (int, error) {
	count := 0
	seen := make(map[plumbing.Hash]bool)
	for !hash.IsZero() {
		if seen[hash] {
			return 0, fmt.Errorf("commit cycle at %s", hash)
		}
		seen[hash] = true
		commit, err := repo.CommitObject(hash)
		if errors.Is(err, plumbing.ErrObjectNotFound) && count > 0 {
			return count, nil
		}
		if err != nil {
			return 0, err
		}
		count++
		if len(commit.ParentHashes) == 0 {
			break
		}
		hash = commit.ParentHashes[0]
	}
	return count, nil
}

func sortEventSignals(events []jsonlSignal) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].Check != events[j].Check {
			return events[i].Check < events[j].Check
		}
		if events[i].Kind != events[j].Kind {
			return events[i].Kind < events[j].Kind
		}
		if events[i].Name != events[j].Name {
			return events[i].Name < events[j].Name
		}
		return events[i].Value < events[j].Value
	})
}
