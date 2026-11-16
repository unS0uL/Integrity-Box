package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Sources of the fingerprint contour (design §5). Tier "archive" is the release asset set that
// MeowDump publishes next to the keybox tiers: meow.prop is the current Canary fingerprint and
// every banned-*.prop is a fingerprint the maintainer withdrew. Tier "google" is the independent
// generator (pif_google.go).
const (
	pifArchiveBase = "https://github.com/MeowDump/Integrity-Box/releases/download/archive/"
	pifReleaseAPI  = "https://api.github.com/repos/MeowDump/Integrity-Box/releases/tags/archive"
	pifMaxBanned   = 8   // banned-* files read per refresh
	pifMaxSet      = 128 // remembered denylist entries
)

var (
	pifBannedName     = regexp.MustCompile(`^banned-[a-z0-9._-]{1,60}\.prop$`)
	pifFallbackBanned = []string{"banned-october-meow.prop"} // when the release listing is unreachable
	pifIDLine         = regexp.MustCompile(`(?m)^(ID|FINGERPRINT)=([A-Za-z0-9 ._:/+()-]{1,200})\s*$`)
)

func (e *Engine) pifBannedPath() string { return filepath.Join(e.brain, ".autopilot-pif-banned.json") }

// loadBanned restores the denylist remembered across reboots. Corruption reads as empty: this
// memory must never be able to block the updater.
func (e *Engine) loadBanned() {
	if e.pifBanned != nil {
		return
	}
	e.pifBanned = map[string]bool{}
	b, err := readLimited(e.pifBannedPath(), 32<<10)
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(b, &list) != nil || len(list) > pifMaxSet {
		return
	}
	for _, v := range list {
		if pifValue.MatchString(v) {
			e.pifBanned[v] = true
		}
	}
}

// bannedNames lists banned-*.prop assets of the release; a failed listing falls back to the
// names already known, so a network hiccup never forgets a ban.
func (e *Engine) bannedNames(ctx context.Context) []string {
	body, err := e.get(ctx, pifReleaseAPI, 256<<10)
	if err != nil {
		return pifFallbackBanned
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if json.Unmarshal(body, &rel) != nil {
		return pifFallbackBanned
	}
	var names []string
	for _, a := range rel.Assets {
		if pifBannedName.MatchString(a.Name) {
			names = append(names, a.Name)
		}
	}
	sort.Strings(names)
	if len(names) > pifMaxBanned {
		names = names[len(names)-pifMaxBanned:] // newest by name suffix is not guaranteed; keep a bounded tail
	}
	if len(names) == 0 {
		return pifFallbackBanned
	}
	return names
}

// refreshBanned rebuilds the denylist from the source. The set is only replaced when at least one
// file was read, and only persisted when it changed.
func (e *Engine) refreshBanned(ctx context.Context) error {
	e.loadBanned()
	fresh := map[string]bool{}
	read := 0
	for _, name := range e.bannedNames(ctx) {
		body, err := e.get(ctx, pifArchiveBase+name, pifMaxBytes)
		if err != nil {
			continue
		}
		read++
		for _, m := range pifIDLine.FindAllStringSubmatch(strings.ReplaceAll(string(body), "\r", ""), -1) {
			fresh[strings.TrimSpace(m[2])] = true
		}
	}
	if read == 0 {
		return errors.New("no banned list readable")
	}
	if len(fresh) > pifMaxSet {
		return errors.New("banned list too large")
	}
	same := len(fresh) == len(e.pifBanned)
	for k := range fresh {
		same = same && e.pifBanned[k]
	}
	if same {
		return nil
	}
	e.pifBanned = fresh
	list := make([]string, 0, len(fresh))
	for k := range fresh {
		list = append(list, k)
	}
	sort.Strings(list)
	return writeJSON(e.pifBannedPath(), list)
}

func (e *Engine) pifRejectedPath() string {
	return filepath.Join(e.brain, ".autopilot-pif-rejected.json")
}

func pifIdentity(f pifFile) string {
	return sha256Hex([]byte(f.Props["FINGERPRINT"] + "|" + f.patch()))
}

func (e *Engine) pifRejectedList() []string {
	b, err := readLimited(e.pifRejectedPath(), 8192)
	if err != nil {
		return nil
	}
	var hashes []string
	if json.Unmarshal(b, &hashes) != nil || len(hashes) > maxRejected {
		return nil
	}
	return hashes
}

func (e *Engine) pifWasRejected(f pifFile) bool {
	id := pifIdentity(f)
	for _, h := range e.pifRejectedList() {
		if h == id {
			return true
		}
	}
	return false
}

func (e *Engine) pifRemember(f pifFile) error {
	if e.pifWasRejected(f) {
		return nil
	}
	hashes := append(e.pifRejectedList(), pifIdentity(f))
	if len(hashes) > maxRejected {
		hashes = hashes[len(hashes)-maxRejected:]
	}
	return writeJSON(e.pifRejectedPath(), hashes)
}

// pifEligible decides whether cand may replace the installed fingerprint. Returns a reason when not.
func (e *Engine) pifEligible(cand, cur pifFile, curState string, now time.Time, pol PIFPolicy) (bool, string) {
	switch {
	case e.pifBanned[cand.Props["ID"]] || e.pifBanned[cand.Props["FINGERPRINT"]]:
		return false, "candidate_banned"
	case e.pifWasRejected(cand):
		return false, "candidate_rejected_before"
	case cur.Props["ID"] != "" && cand.Props["ID"] == cur.Props["ID"] && cand.Props["FINGERPRINT"] == cur.Props["FINGERPRINT"]:
		return false, "same_build"
	}
	candExp := cand.expiry(pol.Lifetime)
	if !candExp.IsZero() && !now.Before(candExp) {
		return false, "candidate_expired"
	}
	switch curState {
	case "banned", "expired", "absent":
		return true, "" // anything valid beats a withdrawn or dead fingerprint
	case "expiring", "ok":
		if curState == "ok" && !pol.FollowLatest {
			return false, "follow_latest_off"
		}
		curExp := cur.expiry(pol.Lifetime)
		if !curExp.IsZero() && !candExp.IsZero() && !candExp.After(curExp) {
			return false, "not_newer"
		}
		if candExp.IsZero() && !curExp.IsZero() {
			return false, "candidate_expiry_unknown"
		}
		return true, ""
	}
	return false, "state_" + curState
}

// pifFindCandidate walks the configured sources in order and returns the first eligible candidate.
func (e *Engine) pifFindCandidate(ctx context.Context, cur pifFile, curState string, pol PIFPolicy) (*pifFile, string) {
	reason := "no_source"
	for _, src := range pol.Sources {
		var cand pifFile
		var err error
		switch src {
		case "archive":
			var body []byte
			if body, err = e.get(ctx, pifArchiveBase+"meow.prop", pifMaxBytes); err == nil {
				cand, err = parsePIF(body)
			}
		case "google":
			cand, err = e.pifGoogleCandidate(ctx, pol)
		default:
			continue
		}
		if err != nil {
			reason = src + "_unavailable"
			continue
		}
		ok, why := e.pifEligible(cand, cur, curState, time.Now(), pol)
		if ok {
			return &cand, ""
		}
		reason = src + ":" + why
	}
	return nil, reason
}

func (e *Engine) pifGoogleCandidate(ctx context.Context, pol PIFPolicy) (pifFile, error) {
	return pifFile{}, errors.New("google source not available")
}
