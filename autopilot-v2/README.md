# AutoPilot v2

ARM64 Android engine with POSIX entry points. Build with `./build.sh` from this directory (Go 1.24+, validated with Go 1.27.2). No third-party Go dependencies. Binary uses Android's native curl for netd/bionic DNS; HTTPS verification remains enabled. Google attestation trust anchors are embedded from https://android.googleapis.com/attestation/root (retrieved 2026-11-07); public-key pinning permits equivalent reissued roots. Root changes require a reviewed rebuild.

`webroot/common_scripts/autopilot.sh` commands:

- `status`: JSON with desired enablement, verified daemon lock ownership, current local certificate health, revocation freshness and next deadline. Integrity verdict is explicitly not measured by this engine.
- `enable`: persist enable flag and detach one supervised daemon. First ordinary check is due after approximately two minutes, subject to screen/charging/battery/temperature gates.
- `disable`: remove enable flag, signal verified supervisor identity and wait up to 35 seconds for cancellation/transaction completion. Failure is reported rather than claiming stopped.
- `start`: idempotent detached service start if enabled, used by boot.
- `probe`: bounded network search and validation without installation. Diagnostic status and locks live in a separate RAM subdirectory.
- `run-once`: explicit manual update via normal priority cascade; not used to trigger the final natural recovery experiment.
- `import PATH [1|2|3]`: validate and transactionally import exactly the requested file; no fallback to unrelated sources.

Official `key.sh` and `spectre.sh` entry points delegate to the same engine. All automatic requests share one RAM search lock. All installations share one RAM write lock. Disabled autoservice does not prevent an explicitly requested manual import/update.

Source order: skip-default enabled -> secondary, Megatron, emergency Megatron2; otherwise Megatron, secondary, Megatron2. The emergency tier is attempted only if the existing certificate is unusable/revoked. A valid existing certificate is preserved on transport errors or inferior replacement. Names/expiry never imply two integrity verdicts. Any rejected/unchanged secondary candidate advances to the next bounded candidate rather than aborting the source.

Limits: one search deadline 90 seconds, secondary 45 seconds, each HTTP operation 10 seconds (connect 4), up to five unique secondary payloads plus one attempt per official tier. HTTPS host/redirect allowlist, maximum five redirect hops. Catalog/payload/XML limit 1 MiB; revocation response 4 MiB (live response around 181 KiB). Runtime Go memory target 32 MiB is a soft GC target, not a hard RSS limit. No global DNS, SELinux policy, wakelock, reboot, keystore kill or system power-profile changes.

Retries: 30 minutes, two hours, six hours, then up to twelve hours indefinitely, with jitter. Retry-After cooldown is per host, bounded to 30 minutes–24 hours. Charger reconnect can accelerate due work only after a 30-minute attempt cooldown. CRL has its own freshness window (Cache-Control clamped to 30 minutes–12 hours); ETag/Last-Modified conditional requests supported. CRL failure is unknown/stale, never a successful verdict. Cached evidence and search cursor are RAM-only and reset after reboot.

The scheduler uses /proc/uptime for suspend-aware deadlines. No alarm wakes a suspended phone: work is postponed until an ordinary eligible wake. On battery, screen off or low battery defers work; external supply is detected through usb/pc_port/dc online, including Not charging at a charge limit. A 25-second grace is measured after the screen is observed on; polling may delay work further. Two lightweight service loops poll at most once a minute in steady state. Supervisor doesn't use stale heartbeat to kill a suspended child.

Installation: parse XML/DER, validate private/public pairing, chain signatures, supplied trusted root and dates. File write transaction is staged on each target filesystem, preserves existing ownership/mode/context, journals bounded original copies, renames and syncs directories, verifies bytes and retains one previous backup. Recovery rolls unfinished transactions back. Main and enabled TEE-SIM/OMK consumers are prepared together; multiple paths cannot have a globally atomic rename. The journal handles interruption, but cannot make external consumers observe a simultaneous multi-file change. Tricky Store documents immediate config reload; no unconditional keystore restart is used. Other consumer-specific reload behavior remains a runtime compatibility concern.

Tests: host race detector, vet, POSIX ShellCheck, JavaScript parsing; the Go test binary also runs under Android root in a private RAM directory. Android-only tests exercise SELinux labels, actual same-filesystem commits and journal recovery using synthetic fixtures, never the working keybox. Device identity and rollback copies are documented outside the module in the project implementation record.

Known verification limits: unit tests/fault scenarios are not certification of every ROM, actual power loss, all optional consumers or 48-hour battery behavior. Service acceptance does not guarantee Play Integrity acceptance. Real verdicts require the checker application and an unlocked UI. Legacy action.sh retains its unrelated broader operations; AutoPilot never invokes that action.

## Completion hardening (2026-11-07)

The updater now restores pending transactions before the framework/power gate,
preflights all backup files, and uses v1 checksummed journals (v0 recovery retained
for migration). Slots 1–3 share the recovery allowlist. CRL-only checks preserve the
independent replacement deadline and failure count; a new revocation identity can
accelerate one search subject to the 30-minute minimum and host rate limits.

Before writes, Android14 `cmd time_detector get_network_time` is checked with a
4-second bound, sample age at most24h, uncertainty at most60s and current-clock
agreement within5min. `/proc/uptime` precision is accounted for. Unsupported/stale
responses block automatic/manual updates rather than assuming correctness. This
is a platform-specific time-evidence adapter, not a guarantee for other ROMs.
`clock-status` exposes its current result without changing the keybox.

`configure FLAG on|off` controls autopilot/disable-default-source/omk-key/sim-key.
It serializes mutations and increments a persistent revision on actual changes;
install takes writer then config lock, config mutations take only config lock.
External legacy touch/rm cannot provide the same ABA guarantee and should migrate
to this entry point. Imports now require a fresh CRL. UI shows their failure text.

New status fields include ready, time_state, next_search_due, next_crl_due and
installed_source. Installed source is unknown when RAM provenance is missing;
`source` remains the last attempted tier. Emergency Megatron2 fingerprints are
recorded durably before installation, so restart does not stop upgrade attempts.
A verified non-anchor candidate may have shorter lifetime than the emergency
anchor. Pre-existing unclassified files are not declared anchors from dates or
Subject strings alone.

Worker stderr is bounded in RAM and classified; its raw text is not logged.
Exit codes and sanitized HTTP/telemetry failures go to logcat. No timing behavior
is claimed from process presence alone. `observe.py` optionally records bounded,
read-only hourly status/hash samples on the host; transport gaps are missing
evidence, and this sampling is not an A/B battery benchmark.

Final validation hardening rejects ambiguous XML scalar fields/namespaces and
non-CA signing certificates, and performs full X.509 path validation. The stable
identity of an emergency keybox is derived from leaf certificate DER, so XML
formatting cannot bypass anchor recognition; raw file hashes still protect CAS.
Revocation entries must have canonical certificate serials and known statuses;
a malformed response cannot erase previously known revocations. Runtime metadata
has explicit byte limits. A corrupt config revision blocks installation but does
not prevent stopping the service. Pilot displays verified process liveness rather
than interpreting an old heartbeat during suspend as a dead process.
