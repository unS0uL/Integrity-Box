package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Configuration section used when there is no previous file to inherit it from (same defaults
// the module ships).
const pifDefaultTail = `# Configuration
spoofBuild=1
spoofProps=1
spoofPixel=1
spoofApps=1
spoofPhotos=1
spoofPatch=1
spoofVendingFinger=0
spoofProvider=0
spoofSignature=0
spoofVendingSdk=0
verboseLogs=0`

// pifApplied matches the line Play Integrity Fork logs when it spoofs a process.
var pifApplied = regexp.MustCompile(`PIF/Java:DG: \[FINGERPRINT\]: .* -> (.+?)\s*$`)

// pifMaintain is the time-dependent half of the contour: refresh the denylist, audit with a
// verified clock, repair the patch pair, and replace a withdrawn/expired/expiring fingerprint.
// It never returns an error to the caller: the keybox contour must not depend on it.
func (e *Engine) pifMaintain(ctx context.Context, automatic bool) {
	if !e.pifActive() || e.dryRun {
		return
	}
	pol := e.pifPolicy()
	timeOK := e.status.TimeState == "verified"
	e.loadBanned()
	if timeOK && (!automatic || e.uptime() >= e.pifBannedDue) {
		wait := 6 * time.Hour
		if err := e.refreshBanned(ctx); err != nil {
			wait = 2 * time.Hour
		}
		e.pifBannedDue = e.uptime() + wait.Seconds()
	}
	cur, patch := e.pifAudit(timeOK)
	if err := e.pifSyncPatch(cur, patch); err != nil {
		logEvent("pif_cycle_error", "local", 0)
	}
	if pol.Mode != "auto" || !timeOK {
		return
	}
	state := e.status.PIF.State
	if !(state == "banned" || state == "expired" || state == "expiring" || state == "ok" && pol.FollowLatest) {
		return
	}
	if automatic && e.uptime() < e.pifSearchDue {
		return
	}
	cand, why := e.pifFindCandidate(ctx, cur, state, pol)
	if cand == nil {
		wait := 6 * time.Hour
		if strings.HasSuffix(why, "_unavailable") {
			wait = 2 * time.Hour
		}
		e.pifSearchDue = e.uptime() + wait.Seconds()
		e.status.PIF.Reason = "no_replacement:" + why
		logEvent("pif_no_replacement", "local", 0)
		e.publish()
		return
	}
	if err := e.pifInstall(ctx, *cand, cur); err != nil {
		e.pifSearchDue = e.uptime() + (2 * time.Hour).Seconds()
		e.status.PIF.Reason = "install_failed: " + err.Error()
		logEvent("pif_install_failed", "local", 0)
	}
	e.publish()
}

// pifInstall writes the candidate, proves the write by reading it back, repairs the patch pair,
// then asks Play Services to restart and looks for the spoof in the log. Nothing is kept on
// disk as a backup (rule: no copies on the phone); the previous bytes live in memory only until
// the install is settled.
func (e *Engine) pifInstall(ctx context.Context, cand, cur pifFile) error {
	pol := e.pifPolicy()
	wl, err := lock(filepath.Join(e.ram, "write.lock"))
	if err != nil {
		return errors.New("write lock busy")
	}
	defer wl.Close()
	prop := e.pifPropPath()
	orig, absent, err := readOptional(prop, pifMaxBytes)
	if err != nil {
		return err
	}
	tail := pifDefaultTail
	if cur.Tail != "" {
		tail = cur.Tail
	}
	data := cand.render(tail, cand.releaseDate(), cand.expiry(pol.Lifetime), time.Now().Format("2006-01-02"))
	if _, err = parsePIF(data); err != nil {
		return errors.New("rendered file invalid: " + err.Error())
	}
	restore := func() {
		if !absent {
			_ = e.writeMeta(prop, orig, 0644)
		}
	}
	if err = e.writeMeta(prop, data, 0644); err != nil {
		return err
	}
	back, _, err := readOptional(prop, pifMaxBytes)
	if err != nil || !bytes.Equal(back, data) {
		restore()
		return errors.New("readback differs; previous file restored")
	}
	f, pf := e.pifAudit(true)
	if err = e.pifSyncPatch(f, pf); err != nil {
		restore()
		e.pifAudit(true)
		return errors.New("patch pair repair failed; previous file restored: " + err.Error())
	}
	if e.status.PIF.PatchPair == "mismatch" {
		restore()
		e.pifAudit(true)
		return errors.New("patch pair still mismatched; previous file restored")
	}
	applied, evidence := e.pifProbe(ctx, cand)
	e.status.PIF.Applied, e.status.PIF.Evidence, e.status.PIF.Action = applied, evidence, "installed"
	e.status.PIF.Reason = ""
	logEvent("pif_installed", "local", 0)
	return nil
}

func (e *Engine) restartPlayServices(ctx context.Context) error {
	if e.restartGMS != nil {
		return e.restartGMS(ctx)
	}
	// killall exits non-zero when the process is not running, which is fine: it starts on demand.
	_ = exec.CommandContext(ctx, "killall", "com.google.android.gms.unstable").Run()
	return nil
}

// pifProbe restarts Play Services and looks, after a marker with a random code, for the line in
// which PIF reports spoofing the candidate. Result is accepted|unknown only: PIF never says
// "refused", so silence is never read as acceptance and never causes a rollback (Law 6).
func (e *Engine) pifProbe(ctx context.Context, cand pifFile) (string, string) {
	pol := e.pifPolicy()
	if !pol.Probe {
		return "not_probed", "disabled"
	}
	var logs logChannel = androidLog{} // same default as the consumer probe (probe.go)
	if e.logs != nil {
		logs = e.logs
	}
	nonce := newNonce()
	if err := logs.Mark(ctx, nonce); err != nil {
		return "unknown", "no_log_channel"
	}
	_ = e.restartPlayServices(ctx)
	poll := e.probePoll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	deadline := time.Now().Add(pol.ProbeWait)
	evidence := "marker_not_visible"
	for {
		lines, err := logs.Lines(ctx)
		if err == nil {
			if after, seen := linesAfterMarker(lines, nonce); seen {
				evidence = "no_spoof_line"
				for i := len(after) - 1; i >= 0; i-- {
					if m := pifApplied.FindStringSubmatch(after[i]); m != nil {
						if strings.TrimSpace(m[1]) == cand.Props["FINGERPRINT"] {
							return "accepted", "applied_in_log"
						}
						evidence = "different_fingerprint_seen"
					}
				}
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return "unknown", evidence
		}
		select {
		case <-ctx.Done():
			return "unknown", evidence
		case <-time.After(poll):
		}
	}
}
