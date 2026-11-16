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
	pifMaxBanned   = 16  // banned-* files read per refresh
	pifMaxSet      = 256 // remembered denylist entries
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
	b, err := readLimited(e.pifBannedPath(), 64<<10)
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
	e.pifBannedKnown = true // a denylist read at least once earlier is remembered across reboots
}

// bannedNames lists banned-*.prop assets of the release in the API's own (upload) order and keeps
// the newest pifMaxBanned. A failed listing falls back to the one name known to exist; the bans
// already remembered are never dropped (see refreshBanned), so a rate-limited API only delays news.
func (e *Engine) bannedNames(ctx context.Context) (names []string, listed bool) {
	body, err := e.get(ctx, pifReleaseAPI, 256<<10)
	if err != nil {
		return pifFallbackBanned, false
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if json.Unmarshal(body, &rel) != nil {
		return pifFallbackBanned, false
	}
	seen := map[string]bool{}
	for _, a := range rel.Assets {
		if pifBannedName.MatchString(a.Name) && !seen[a.Name] {
			seen[a.Name] = true
			names = append(names, a.Name)
		}
	}
	if len(names) > pifMaxBanned {
		names = names[len(names)-pifMaxBanned:]
	}
	// A listing that worked but holds no banned-*.prop is a real answer ("nothing withdrawn yet"), not a failure.
	return names, true
}

// refreshBanned merges the maintainer's banned-*.prop files into the remembered denylist. A ban is a
// fact about a build: it is never forgotten because a file could not be read this time. At least
// one file must be readable, otherwise the refresh fails and the caller fails closed.
func (e *Engine) refreshBanned(ctx context.Context) error {
	e.loadBanned()
	fresh := map[string]bool{}
	read := 0
	names, listed := e.bannedNames(ctx)
	if listed && len(names) == 0 {
		e.pifBannedKnown = true // an authoritative empty list: nothing is withdrawn, remembered bans stay
		return nil
	}
	for _, name := range names {
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
	merged := make(map[string]bool, len(e.pifBanned)+len(fresh))
	for k := range e.pifBanned {
		merged[k] = true
	}
	for k := range fresh {
		merged[k] = true
	}
	if len(merged) > pifMaxSet {
		// The memory is full of old bans: keep what the source lists now (older builds are long expired).
		logEvent("pif_denylist_capped", "local", len(merged))
		merged = fresh
		if len(merged) > pifMaxSet {
			return errors.New("banned list too large")
		}
	}
	e.pifBannedKnown = true
	changed := len(merged) != len(e.pifBanned)
	for k := range merged {
		changed = changed || !e.pifBanned[k]
	}
	if !changed {
		return nil
	}
	e.pifBanned = merged
	list := make([]string, 0, len(merged))
	for k := range merged {
		list = append(list, k)
	}
	sort.Strings(list)
	return writeJSON(e.pifBannedPath(), list)
}

// pifEligible decides whether cand may replace the installed fingerprint. Returns a reason when not.
func (e *Engine) pifEligible(cand, cur pifFile, curState string, now time.Time, pol PIFPolicy) (bool, string) {
	switch {
	case e.pifBanned[cand.Props["ID"]] || e.pifBanned[cand.Props["FINGERPRINT"]]:
		return false, "candidate_banned"
	case cur.Props["ID"] != "" && cand.Props["ID"] == cur.Props["ID"] && cand.Props["FINGERPRINT"] == cur.Props["FINGERPRINT"]:
		return false, "same_build"
	}
	// The patch is not taken on trust: it must not lie in the future beyond the next monthly patch
	// and must sit near the build date (canary-YYYYMM carries the YYYY-MM-05 patch).
	if pt, err := time.Parse("2006-01-02", cand.patch()); err != nil || pt.After(now.AddDate(0, 0, 62)) {
		return false, "candidate_patch_in_future"
	} else if rel := cand.releaseDate(); !rel.IsZero() && (pt.Before(rel.AddDate(0, 0, -35)) || pt.After(rel.AddDate(0, 0, 125))) {
		return false, "candidate_patch_far_from_build"
	}
	candExp := cand.expiry(pol.Lifetime)
	if !candExp.IsZero() && !now.Before(candExp) {
		return false, "candidate_expired"
	}
	switch curState {
	case "banned", "expired":
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
			cand, err = e.pifGoogleCandidate(ctx, cur)
		default:
			continue
		}
		if err != nil {
			reason = src + "_unavailable"
			continue
		}
		// Dates inside remote content are not believed: they are derived from the build id.
		cand.Released, cand.Expires = time.Time{}, time.Time{}
		ok, why := e.pifEligible(cand, cur, curState, e.now(), pol)
		if ok {
			return &cand, ""
		}
		reason = src + ":" + why
	}
	return nil, reason
}
