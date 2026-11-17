#!/usr/bin/env python3
"""Create and verify a deterministic module package, without device installation."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z']).decode().split('\0')
    # Development files never ship: dot-files (.gitignore, .gitmodules, .gitguard-allow, .github/), tests, docs.
    names = {n for n in names if n and not n.startswith(('autopilot-v2/', 'docs/', 'assets/'))
             and not any(part.startswith('.') for part in n.split('/'))
             and n not in ('hash', 'README.md', 'changelog.md')}
    names.update(('webroot/common_scripts/bin/box-autopilot', 'webroot/common_scripts/bin/GO-LICENSE'))
    # A shipped file must be exactly what is committed (the engine's provenance is checked against HEAD).
    dirty = subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--'] + sorted(names)).decode().strip()
    if dirty:
        raise RuntimeError('refusing to package files that differ from HEAD:\n' + dirty)
    verified = subprocess.run(['sh', str(repo / 'autopilot-v2/verify_binary.sh')], capture_output=True, text=True)
    if verified.returncode != 0:
        raise RuntimeError('the engine binary is not verified against the committed source '
                           '(exit %d; 3 = built with another Go toolchain):\n%s%s' % (verified.returncode, verified.stdout, verified.stderr))
    files = {n: (repo / n).read_bytes() for n in sorted(names) if (repo / n).is_file()}
    # The manifest lists what the installer extracts. Magisk/KernelSU unpack with `unzip -x 'META-INF/*'`, so
    # META-INF must NOT be in it (verify.sh refuses a manifest entry whose file is missing) - but it must be in the zip.
    manifest = ''.join(n + '|' + hashlib.sha256(data).hexdigest() + '\n'
                       for n, data in sorted(files.items()) if not n.startswith('META-INF/'))
    files['hash'] = manifest.encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name)
            executable = name.endswith('.sh') or name.endswith(('box-autopilot', 'update-binary'))
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=6)
    with zipfile.ZipFile(args.output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('ZIP CRC verification failed')
        with tempfile.TemporaryDirectory(prefix='box-package-') as directory:
            if 'META-INF/com/google/android/update-binary' not in archive.namelist():
                raise RuntimeError('the package has no META-INF/com/google/android/update-binary')
            # extract the way the installer does: everything except META-INF
            archive.extractall(directory, [n for n in archive.namelist() if not n.startswith('META-INF/')])
            env = dict(os.environ, MODPATH=directory, LC_ALL="C", LC_CTYPE="C", LANG="C")
            if shutil.which('sha256sum') is None:
                if shutil.which('shasum') is None:
                    raise RuntimeError('Host requires sha256sum or shasum')
                tools = Path(directory) / '.host-tools'
                tools.mkdir()
                shim = tools / 'sha256sum'
                shim.write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
                shim.chmod(0o700)
                env['PATH'] = str(tools) + os.pathsep + env.get('PATH', '')
            subprocess.run(['sh', str(Path(directory) / 'verify.sh')], env=env, check=True)
            binary = Path(directory) / 'webroot/common_scripts/bin/box-autopilot'
            binary.write_bytes(binary.read_bytes() + b'corruption-test')
            failed = subprocess.run(['sh', str(Path(directory) / 'verify.sh')], env=env,
                                    capture_output=True)
            if failed.returncode == 0:
                raise RuntimeError('Corrupted package passed verification')
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix('.zip.sha256').write_text(digest + '  ' + args.output.name + '\n')
    print('Package and corruption rejection verified:', digest)


if __name__ == '__main__':
    main()
