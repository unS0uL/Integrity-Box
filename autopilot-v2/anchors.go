package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func (e *Engine) knownAnchors() ([]string, error) {
	b, err := readLimited(filepath.Join(e.brain, ".autopilot-known-anchors.json"), 8192)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 8192 {
		return nil, errors.New("anchor metadata size")
	}
	var hashes []string
	if json.Unmarshal(b, &hashes) != nil || len(hashes) > 64 {
		return nil, errors.New("invalid anchor metadata")
	}
	for _, h := range hashes {
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			return nil, errors.New("invalid anchor hash")
		}
	}
	return hashes, nil
}
func (e *Engine) isKnownAnchor(hash string) bool {
	hashes, err := e.knownAnchors()
	if err != nil {
		return false
	}
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}
func (e *Engine) rememberAnchor(hash string) error {
	hashes, err := e.knownAnchors()
	if err != nil {
		return err
	}
	for _, h := range hashes {
		if h == hash {
			return nil
		}
	}
	if len(hashes) >= 64 {
		return errors.New("anchor metadata capacity reached")
	}
	hashes = append(hashes, hash)
	return writeJSON(filepath.Join(e.brain, ".autopilot-known-anchors.json"), hashes)
}
