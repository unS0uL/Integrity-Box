"""Mutation harness for the PIF contour (run after changing pif*.go): every mutation is applied to an in-memory copy of the originals, tested, and
ALWAYS undone in `finally`. Exit status reflects survivors. Usage: python3 mutate_pif.py <autopilot-v2 dir>; every mutation must be reported as killed"""
import subprocess
import sys

D = sys.argv[1].rstrip('/') + '/'
FILES = ['pif.go', 'pif_engine.go', 'pif_install.go', 'pif_source.go', 'pif_google.go', 'transport.go']
ORIG = {f: open(D + f).read() for f in FILES}
RUN = 'PIF|Maintain|Probe|Eligibility|RefreshBanned|Patch|Incident|Audit|Classify|Release|Denylist|Google|NewestCanary|Generated|Remote|Install|Strict|Failed|Cooldown|Budget|DoctorAgrees'

M = [
    ("denylist replaced instead of merged", 'pif_source.go', '	merged := make(map[string]bool, len(e.pifBanned)+len(fresh))\n	for k := range e.pifBanned {\n		merged[k] = true\n	}', '	merged := make(map[string]bool, len(fresh))'),
    ("fail-closed gate removed", 'pif_install.go', 'if !e.pifBannedKnown {', 'if false {'),
    ("patch sanity removed (future)", 'pif_source.go', '|| pt.After(now.AddDate(0, 0, 62)) {', '|| false {'),
    ("patch sanity removed (vs build)", 'pif_source.go', '(pt.Before(rel.AddDate(0, 0, -35)) || pt.After(rel.AddDate(0, 0, 125)))', 'false'),
    ("remote dates believed", 'pif_source.go', '		cand.Released, cand.Expires = time.Time{}, time.Time{}', '		_ = cand'),
    ("expiry clamp removed", 'pif.go', 'if !r.IsZero() && f.Expires.After(r.Add(2*lifetime)) {', 'if false {'),
    ("stale tail used", 'pif_install.go', '		if now.Tail != "" {\n			tail = now.Tail\n		}', '		if cur.Tail != "" {\n			tail = cur.Tail\n		}'),
    ("changed-during-search guard removed", 'pif_install.go', 'if perr != nil || now.Props["FINGERPRINT"] != cur.Props["FINGERPRINT"] || now.patch() != cur.patch() {', 'if perr != nil {'),
    ("early refusal removed", 'pif_install.go', 'if !pol.SyncPatch && pf.Kind != "stock" && pf.Kind != "none" && pf.pair(cand.patch()) != "match" {', 'if false && pf.Kind != "" {'),
    ("restore does not realign patch", 'pif_install.go', '	_ = e.pifSyncPatch(f, p)\n}\n\nfunc (e *Engine) restartPlayServices', '	_, _ = f, p\n}\n\nfunc (e *Engine) restartPlayServices'),
    ("pif scope not set", 'pif_install.go', '	e.scope = pifScope', '	e.scope = ""'),
    ("strict context ignored", 'pif_engine.go', 'case e.strictContext:', 'case false:'),
    ("budget removed", 'pif_install.go', 'ctx, cancel := context.WithTimeout(parent, pifBudget)', 'ctx, cancel := context.WithCancel(parent)'),
    ("backoff flat", 'pif_install.go', '		d *= 2', '		d += 0'),
    ("names sorted/oldest kept", 'pif_source.go', '		names = names[len(names)-pifMaxBanned:]', '		names = names[:pifMaxBanned]'),
    ("stale cleanup removes everything", 'pif_engine.go', 'time.Since(info.ModTime()) > age', 'time.Since(info.ModTime()) > -age'),
    ("scoped cooldown not scoped", 'transport.go', 'e.hostNext[e.scope+u.Hostname()] = time.Now().Add(delay)', 'e.hostNext[u.Hostname()] = time.Now().Add(delay)'),
    ("write lock skipped", 'pif_install.go', '	wl, err := lock(filepath.Join(e.ram, "write.lock"))\n	if err != nil {\n		return errors.New("write lock busy")\n	}\n	defer wl.Close()', '	var err error'),
    ("probe restart skipped", 'pif_install.go', '	_ = e.restartPlayServices(ctx)', '	_ = ctx'),
    ("readback not checked", 'pif_install.go', 'if err != nil || !bytes.Equal(back, data) {', 'if err != nil || !bytes.Equal(back, data) && false {'),
]


def restore():
    for f, s in ORIG.items():
        open(D + f, 'w').write(s)


bad = 0
try:
    base = subprocess.run(['go', 'test', '-count=1', '-run', RUN, './...'], cwd=D, capture_output=True, text=True)
    if base.returncode != 0:
        print('BASELINE RED, aborting:\n', base.stdout[-800:], base.stderr[-400:])
        sys.exit(2)
    for desc, f, a, b in M:
        restore()
        s = ORIG[f]
        if s.count(a) != 1:
            print(f'SETUP FAIL ({s.count(a)} matches): {desc}')
            bad += 1
            continue
        open(D + f, 'w').write(s.replace(a, b, 1))
        build = subprocess.run(['go', 'build', '-o', '/dev/null', '.'], cwd=D, capture_output=True, text=True)
        if build.returncode != 0:
            print(f'NOT COMPILABLE (mutation proves nothing): {desc}: {build.stderr.strip().splitlines()[-1][:90]}')
            bad += 1
            continue
        r = subprocess.run(['go', 'test', '-count=1', '-run', RUN, './...'], cwd=D, capture_output=True, text=True)
        if r.returncode == 0:
            print('SURVIVED (bad):', desc)
            bad += 1
        else:
            print('killed (good):', desc)
finally:
    restore()
chk = subprocess.run(['go', 'test', '-count=1', '-run', RUN, './...'], cwd=D, capture_output=True, text=True)
print('restored, baseline green:', chk.returncode == 0)
sys.exit(1 if bad else 0)
