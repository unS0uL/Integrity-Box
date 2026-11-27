#!/usr/bin/env python3
"""Bounded, read-only hourly observations of the authorized daily phone."""
import argparse
import datetime
import json
from pathlib import Path
import shlex
import subprocess
import time


def sample(serial):
    command = ('[ "$(getprop ro.serialno)" = ' + shlex.quote(serial) + ' ] || exit 90; '
               'getprop ro.serialno; '
               'sh /data/adb/modules/playintegrityfix/webroot/common_scripts/autopilot.sh status; '
               'sha256sum /data/adb/tricky_store/keybox.xml')
    result = subprocess.run(['adb', '-s', serial, 'shell', 'su -c ' + shlex.quote(command)],
                            capture_output=True, text=True, timeout=20, check=True)
    lines = result.stdout.splitlines()
    if len(lines) != 3 or lines[0] != serial:
        raise ValueError('identity or status response mismatch')
    return {'identity': lines[0], 'status': json.loads(lines[1]),
            'keybox_sha256': lines[2].split()[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--hours', type=float, default=24)
    parser.add_argument('--interval', type=int, default=3600)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if not 0 < args.hours <= 48 or not 300 <= args.interval <= 3600:
        parser.error('hours must be 0..48 and interval 300..3600 seconds')
    repo = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if out == repo or repo in out.parents:
        parser.error('the observation log carries device identity: write it OUTSIDE the repository')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + args.hours * 3600
    first = True
    while first or time.time() < deadline:
        first = False
        record = {'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            record.update(sample(args.serial))
            record['observation'] = 'available'
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            # An unavailable transport is missing evidence, never a healthy sample.
            record.update(observation='unavailable', reason=type(error).__name__)
        with args.output.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record) + '\n')
            stream.flush()
        if args.once:
            break
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(args.interval, remaining))


if __name__ == '__main__':
    main()
