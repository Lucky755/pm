
#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/lucky/pentest-master"
WORK="$ROOT/runtime/executor-workspace"

mkdir -p "$WORK"

bwrap \
  --unshare-all \
  --die-with-parent \
  --new-session \
  --clearenv \
  --setenv PATH /usr/bin:/bin \
  --setenv HOME /work \
  --tmpfs / \
  --ro-bind /usr /usr \
  --ro-bind-try /bin /bin \
  --ro-bind-try /lib /lib \
  --ro-bind-try /lib64 /lib64 \
  --proc /proc \
  --dev /dev \
  --dir /tmp \
  --dir /work \
  --bind "$WORK" /work \
  --chdir /work \
  /usr/bin/sh -c '
    echo "=== ISOLATED EXECUTOR ==="

    echo "[1] Current identity"
    id

    echo "[2] Workspace write"
    printf "sandbox test\n" > /work/test.txt
    cat /work/test.txt

    echo "[3] Access to host secrets"
    if test -e /etc/shadow; then
      echo "UNEXPECTED: /etc/shadow is visible"
    else
      echo "PASS: /etc/shadow is not visible"
    fi

    echo "[4] Write outside workspace"
    if touch /usr/sandbox-test 2>/dev/null; then
      echo "UNEXPECTED: /usr is writable"
      exit 1
    else
      echo "PASS: /usr is read-only"
    fi

    echo "[5] Network namespace"
    cat /proc/net/route

    echo "[DONE] Sandbox test finished"
  '
