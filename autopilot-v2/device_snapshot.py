#!/usr/bin/env python3
"""Read-only Android capability and exact keybox capture. Never starts services."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--output', required=True, type=Path,
                        help='Private backup directory OUTSIDE the repository')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output == repo or repo in output.parents:
        parser.error('Private key backups must be outside the repository')
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)

    def remote(command):
        result = subprocess.run(
            ['adb', '-s', args.serial, 'exec-out', 'su', '-c', command],
            capture_output=True, timeout=30, check=True)
        return result.stdout

    identity = remote('id; getprop ro.serialno; getprop ro.product.device')
    lines = identity.decode().splitlines()
    if (not lines or not lines[0].startswith('uid=0(')
            or lines[1:] != ['bea9a722', 'dipper']):
        raise RuntimeError('Expected rooted daily phone bea9a722/dipper; no keybox captured')
    # Hash before and after the stream: a concurrent replacement invalidates capture.
    target = '/data/adb/tricky_store/keybox.xml'
    before = remote('sha256sum ' + target).decode().split()[0]
    payload = remote('cat ' + target)
    after = remote('sha256sum ' + target).decode().split()[0]
    digest = hashlib.sha256(payload).hexdigest()
    if not payload or before != digest or after != digest:
        raise RuntimeError('Keybox changed or capture incomplete; retry required')
    keyfile = output / 'original-keybox.xml'
    with keyfile.open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    metadata = remote(
        'ls -lnZ /data/adb/tricky_store/keybox.xml; '
        'getenforce; getprop sys.boot_completed; '
        'for n in autopilot disable-default-source run-action omk-key sim-key; do '
        '[ ! -f /data/adb/Box-Brain/$n ] || printf "flag=%s\\n" "$n"; done; '
        'for n in curl openssl jq python3 flock timeout setsid task_profiles busybox; do '
        'command -v "$n" || :; done; '
        'cat /proc/uptime; '
        'ps -A -o PID,PPID,ARGS | grep -E "autopilot|spectre|key.sh" || :'
    ).decode(errors='replace')
    manifest = {'schema': 1, 'serial': args.serial, 'sha256': digest,
                'bytes': len(payload), 'identity': identity.decode(),
                'metadata': metadata, 'services_started': False,
                'device_files_modified': False,
                'integrity_verdict': 'not_measured'}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    # Verify the durable local copy without exposing the private key.
    if hashlib.sha256(keyfile.read_bytes()).hexdigest() != digest:
        raise RuntimeError('Local backup verification failed')
    print(json.dumps({'backup': str(output), 'sha256': digest,
                      'bytes': len(payload), 'device_modified': False}))


if __name__ == '__main__':
    main()
