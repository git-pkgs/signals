package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/ossf/scorecard/v5/clients"
)

type blobCache struct {
	data     map[string][]byte
	requests int
	hits     int
	bytes    int64
}

func newBlobCache() *blobCache {
	return &blobCache{data: make(map[string][]byte)}
}

func (c *blobCache) reader(file *object.File) (io.ReadCloser, error) {
	c.requests++
	key := file.Hash.String()
	if data, ok := c.data[key]; ok {
		c.hits++
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	reader, err := file.Reader()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(reader)
	err = errors.Join(readErr, reader.Close())
	if err != nil {
		return nil, err
	}
	c.data[key] = data
	c.bytes += int64(len(data))
	return io.NopCloser(bytes.NewReader(data)), nil
}

type commitClient struct {
	uri      string
	tree     *object.Tree
	cache    *blobCache
	allowed  map[string]bool
	once     sync.Once
	files    []string
	objects  map[string]*object.File
	filesErr error
}

var _ clients.RepoClient = (*commitClient)(nil)

func newCommitClient(uri string, commit *object.Commit, cache *blobCache, allowed map[string]bool) (*commitClient, error) {
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read commit tree: %w", err)
	}
	return &commitClient{
		uri:     uri,
		tree:    tree,
		cache:   cache,
		allowed: allowed,
		objects: make(map[string]*object.File),
	}, nil
}

func (c *commitClient) InitRepo(clients.Repo, string, int) error {
	return clients.ErrUnsupportedFeature
}
func (c *commitClient) URI() string                { return c.uri }
func (c *commitClient) IsArchived() (bool, error)  { return false, clients.ErrUnsupportedFeature }
func (c *commitClient) LocalPath() (string, error) { return "", clients.ErrUnsupportedFeature }
func (c *commitClient) Close() error               { return nil }

func (c *commitClient) ListFiles(predicate func(string) (bool, error)) ([]string, error) {
	c.once.Do(c.loadFiles)
	if c.filesErr != nil {
		return nil, c.filesErr
	}

	files := make([]string, 0, len(c.files))
	for _, name := range c.files {
		match, err := predicate(name)
		if err != nil {
			return nil, err
		}
		if match {
			files = append(files, name)
		}
	}
	return files, nil
}

func (c *commitClient) GetFileReader(filename string) (io.ReadCloser, error) {
	c.once.Do(c.loadFiles)
	if c.filesErr != nil {
		return nil, c.filesErr
	}
	file, ok := c.objects[filename]
	if !ok {
		return nil, object.ErrFileNotFound
	}
	return c.cache.reader(file)
}

func (c *commitClient) loadFiles() {
	if c.allowed != nil {
		c.loadAllowedFiles()
		return
	}
	iter := c.tree.Files()
	defer iter.Close()
	c.filesErr = iter.ForEach(func(file *object.File) error {
		c.files = append(c.files, file.Name)
		c.objects[file.Name] = file
		return nil
	})
	sort.Strings(c.files)
}

func (c *commitClient) loadAllowedFiles() {
	paths := make([]string, 0, len(c.allowed))
	for path := range c.allowed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file, err := c.tree.File(path)
		if errors.Is(err, object.ErrFileNotFound) {
			continue
		}
		if err != nil {
			c.filesErr = err
			return
		}
		c.files = append(c.files, path)
		c.objects[path] = file
	}
}

func (c *commitClient) GetBranch(string) (*clients.BranchRef, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) GetCreatedAt() (time.Time, error) {
	return time.Time{}, clients.ErrUnsupportedFeature
}

func (c *commitClient) GetDefaultBranchName() (string, error) {
	return "", clients.ErrUnsupportedFeature
}

func (c *commitClient) GetDefaultBranch() (*clients.BranchRef, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) GetOrgRepoClient(context.Context) (clients.RepoClient, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListCommits() ([]clients.Commit, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListIssues() ([]clients.Issue, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListLicenses() ([]clients.License, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListReleases() ([]clients.Release, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListContributors() ([]clients.User, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListSuccessfulWorkflowRuns(string) ([]clients.WorkflowRun, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListCheckRunsForRef(string) ([]clients.CheckRun, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListStatuses(string) ([]clients.Status, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListWebhooks() ([]clients.Webhook, error) {
	return nil, clients.ErrUnsupportedFeature
}

func (c *commitClient) ListProgrammingLanguages() ([]clients.Language, error) {
	return []clients.Language{{Name: clients.All, NumLines: 1}}, nil
}

func (c *commitClient) Search(clients.SearchRequest) (clients.SearchResponse, error) {
	return clients.SearchResponse{}, clients.ErrUnsupportedFeature
}

func (c *commitClient) SearchCommits(clients.SearchCommitsOptions) ([]clients.Commit, error) {
	return nil, clients.ErrUnsupportedFeature
}
