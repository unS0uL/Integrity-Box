p='reconcile.go'
s=open(p).read()
old="""	e.auditConsumer(ctx, !e.dryRun)
"""
new="""	e.auditConsumer(ctx, !e.dryRun)
	// The fingerprint contour is independent of the keybox contour: a failure here is logged and
	// never blocks (or is blocked by) the key. Patch repair needs no network and no clock.
	pifFile, pifPatch := e.pifAudit(e.status.TimeState == "verified")
	if er := e.pifSyncPatch(pifFile, pifPatch); er != nil {
		logEvent("pif_cycle_error", "local", 0)
	}
"""
assert s.count(old)==1
s=s.replace(old,new)
old2="""		if e.status.TimeState == "verified" {
			audit := localAuditDeadline(e.status.Local, time.Now())
			if !audit.IsZero() && audit.Before(next) {
				next = audit
			}
		}
"""
new2=old2+"""		if d := e.pifDeadline(); !d.IsZero() && d.Before(next) {
			next = d
		}
"""
assert s.count(old2)==1
s=s.replace(old2,new2)
open(p,'w').write(s)
p='engine.go'
s=open(p).read()
old="	urgentEvidence    string\n"
assert s.count(old)==1
s=s.replace(old,old+"	pifBanned         map[string]bool // denylisted fingerprint ids and strings (RAM, rebuilt from the source)\n")
open(p,'w').write(s)
p='pif_engine.go'
s=open(p).read()
i=s.index("// cleanPatchText")
s=s[:i].rstrip()+"\n"
s=s.replace('	"strings"\n','')
open(p,'w').write(s)
