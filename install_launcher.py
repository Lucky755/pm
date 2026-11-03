#!/usr/bin/env python3
"""Install a simple user-owned 'pentest-master' command, no system modification."""
from pathlib import Path
import os
import shlex
import stat

root = Path(__file__).resolve().parent
venv = root / '.venv/bin/python'
entry = root / 'pm.py'
if not venv.is_file() or not entry.is_file():
    raise SystemExit('Start this installer from an existing Pentest Master project with .venv')
destination = Path.home() / '.local/bin/pentest-master'
destination.parent.mkdir(parents=True, exist_ok=True)
if destination.is_symlink():
    raise SystemExit(f'Refusing to replace symbolic link: {destination}')
if destination.exists() and 'Pentest Master Console launcher' not in destination.read_text(errors='replace'):
    raise SystemExit(f'Refusing to overwrite unrelated executable: {destination}')
tmp = destination.with_name('.pentest-master.tmp')
if tmp.exists():
    raise SystemExit(f'Temporary file already exists: {tmp}')
script = ('#!/bin/sh\n# Pentest Master Console launcher\n'
          'exec ' + shlex.quote(str(venv)) + ' ' + shlex.quote(str(entry)) + ' "$@"\n')
with tmp.open('x') as f:
    f.write(script)
os.chmod(tmp, 0o755)
os.replace(tmp, destination)
print(f'✓ Installed {destination}')
if str(destination.parent) not in os.environ.get('PATH', '').split(os.pathsep):
    print('Add ~/.local/bin to PATH; in this shell: export PATH="$HOME/.local/bin:$PATH"')
