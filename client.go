package main

import (
	"bytes"
	"errors"
	"io"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/object"
)

type blobCache struct {
	repository    *git.Repository
	data          map[string][]byte
	languagePaths map[string]languagePath
	requests      int
	hits          int
	bytes         int64
}

func newBlobCache(repository *git.Repository) *blobCache {
	return &blobCache{
		repository:    repository,
		data:          make(map[string][]byte),
		languagePaths: make(map[string]languagePath),
	}
}

func (c *blobCache) reader(file *object.File) (io.ReadCloser, error) {
	data, err := c.dataFor(file)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (c *blobCache) dataFor(file *object.File) ([]byte, error) {
	c.requests++
	key := file.Hash.String()
	if data, ok := c.data[key]; ok {
		c.hits++
		return data, nil
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
	return data, nil
}
