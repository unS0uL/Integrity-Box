package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (e *Engine) configLock(ctx context.Context) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		f, err := lock(filepath.Join(e.ram, "config.lock"))
		if err == nil {
			return f, nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("configuration busy")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func (e *Engine) setFlag(ctx context.Context, name string, on bool) error {
	switch name {
	case "autopilot", "disable-default-source", "omk-key", "sim-key":
	default:
		return errors.New("unsupported configuration flag")
	}
	f, err := e.configLock(ctx)
	if err != nil {
		return err
	}
	defer f.Close()
	if exists(filepath.Join(e.brain, name)) == on {
		return nil
	}
	if err = os.MkdirAll(e.brain, 0700); err != nil {
		return err
	}
	path := filepath.Join(e.brain, ".autopilot-config-revision")
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var n uint64
	if len(b) > 0 {
		n, err = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return err
		}
	}
	if n == ^uint64(0) {
		return errors.New("configuration revision exhausted")
	}
	// Revision first: a failed flag write may invalidate work, never authorize stale work.
	if err = atomic(path, []byte(fmt.Sprint(n+1)), 0600); err != nil {
		return err
	}
	if on {
		return atomic(filepath.Join(e.brain, name), nil, 0600)
	}
	return os.Remove(filepath.Join(e.brain, name))
}
