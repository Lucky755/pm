"""Run the original planner with the session key read from an inherited pipe.

The key never appears in argv, environment variable *values*, or on disk.
Only the descriptor number is inherited via PM_SESSION_KEY_FD.
"""
import getpass
import os
from pathlib import Path
import runpy
import sys

fd_text = os.environ.pop('PM_SESSION_KEY_FD', '')
if not fd_text.isdecimal() or not 3 <= int(fd_text) <= 65535:
    raise SystemExit('Missing session descriptor')
fd = int(fd_text)
try:
    secret = os.read(fd, 4097)
finally:
    os.close(fd)
if not secret or len(secret) > 4096:
    raise SystemExit('Invalid session key')
key = secret.decode('utf-8')
getpass.getpass = lambda prompt='Password: ', stream=None: key
if len(sys.argv) < 2:
    raise SystemExit('Missing planner script')
planner = Path(sys.argv[1]).resolve(strict=True)
project = Path(__file__).resolve().parents[1]
if not planner.is_file() or planner != (project / 'orchestrator/planner.py').resolve():
    raise SystemExit('Only the local Pentest Master planner may use this entrypoint')
sys.argv = sys.argv[1:]
sys.path.insert(0, str(project))
sys.path.insert(0, str(planner.parent))
runpy.run_path(str(planner), run_name='__main__')
