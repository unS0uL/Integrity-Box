package main

import (
	"context"
	"net/http"
	"os/exec"
	"path/filepath"
	"time"
)

type Engine struct {
	bootClock         func() float64
	statusErrorAt     time.Time
	timeCheck         func(context.Context) error
	moduleRoot        string
	crlBoot           float64
	crlTTL            time.Duration
	workerCommand     func() *exec.Cmd
	request           func(*http.Request) (*http.Response, error)
	forcedTier        string
	slot              string
	cache             map[string]cacheEntry
	hostNext          map[string]time.Time
	root, ram, brain  string
	dryRun            bool
	client            *http.Client
	status            Status
	revoked           map[string]bool
	crlAt             time.Time
	cursor            int
	automaticFetchDue float64
	searched          bool
	lastSearchBoot    float64
	urgentEvidence    string
	// Consumer verification. Zero values keep the legacy behaviour (used by unit tests).
	modulesRoot          string
	logs                 logChannel
	probeSettle          time.Duration
	probePoll            time.Duration
	lastProbeFingerprint string
	lastProbeBoot        float64
	requireConsumer      bool
	policy               Policy
	consumerSig          string
	consumerSigSet       bool
	// Clock evidence.
	networkClock func(context.Context) error // test hook for the Android network-time probe
	lastDate     string                      // Date header of the latest HTTPS response
	lastDateRTT  time.Duration
}

func (e *Engine) uptime() float64 {
	if e.bootClock != nil {
		return e.bootClock()
	}
	return bootSeconds()
}

func (e *Engine) target() string {
	if e.slot != "" {
		return filepath.Join(e.root, e.slot)
	}
	return filepath.Join(e.root, "keybox.xml")
}

func (e *Engine) enabled() bool {
	return exists(filepath.Join(e.brain, "autopilot")) && (e.moduleRoot == "" || exists(e.moduleRoot) && !exists(filepath.Join(e.moduleRoot, "disable")) && !exists(filepath.Join(e.moduleRoot, "remove")))
}
