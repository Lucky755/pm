#!/usr/bin/env bash
# Install (or remove) a narrowly scoped NOPASSWD rule for the Pentest Master
# root broker so non-interactive callers (MCP server, orchestrator, agents)
# can reach it without a tty.
#
# Why this is needed:
#   sudo password timestamps are tty-scoped on this host, so a process without
#   a controlling terminal can never reuse the operator's cached `sudo -v`
#   ticket. Every caller in this project uses `sudo -n` and would otherwise
#   always fail with "sudo: требуется указать пароль".
#
# The rule grants passwordless root ONLY for /usr/local/sbin/pm-netguard.
# The broker itself enforces task scope (nftables in the root netns), profile
# allowlists, argv restrictions and timeouts, so it is not a general root shell
# for arbitrary paths — but it does run agent-supplied commands as root inside
# the task namespace, which is the documented design of this project.
#
# Usage:
#   scripts/install_netguard_sudoers.sh           # install (asks for sudo password once)
#   scripts/install_netguard_sudoers.sh --remove  # remove the rule
#   scripts/install_netguard_sudoers.sh --check   # report state only

set -euo pipefail

BROKER="/usr/local/sbin/pm-netguard"
TARGET="/etc/sudoers.d/pm-netguard"
# The rule must be granted to the interactive operator, not to root (root needs
# no sudo rule at all). When the script itself is launched through sudo,
# SUDO_USER carries the real operator account.
OWNER="${PM_SUDO_USER:-${SUDO_USER:-$(id -un)}}"

usage() { sed -n '2,25p' "$0"; }

rule_text() {
    cat <<EOF
# Pentest Master: passwordless access to the scoped root broker only.
# Installed by scripts/install_netguard_sudoers.sh — remove with --remove.
${OWNER} ALL=(root) NOPASSWD: ${BROKER}
EOF
}

# Run a command as the operator account, even when this script runs as root.
as_owner() {
    if [[ "$(id -un)" == "$OWNER" ]]; then
        "$@"
    elif [[ "$(id -u)" == "0" ]]; then
        sudo -u "$OWNER" "$@"
    else
        "$@"  # no privilege to switch; verify as current user
    fi
}

check_state() {
    if [[ -f "$TARGET" ]]; then
        echo "rule file: $TARGET (present)"
        sudo -n cat "$TARGET" 2>/dev/null || echo "  (cannot read without sudo)"
    else
        echo "rule file: $TARGET (absent)"
    fi
    if as_owner sudo -n "$BROKER" capabilities >/dev/null 2>&1; then
        echo "sudo -n $BROKER as ${OWNER}: OK"
    else
        echo "sudo -n $BROKER as ${OWNER}: FAILS (interactive password required)"
    fi
}

install_rule() {
    [[ -x "$BROKER" ]] || { echo "broker missing: $BROKER" >&2; exit 1; }
    tmp="$(mktemp /tmp/pm-netguard.sudoers.XXXXXX)"
    trap 'rm -f "${tmp:-}"' EXIT
    rule_text >"$tmp"
    chmod 0440 "$tmp"
    echo "--- candidate rule ---"
    cat "$tmp"
    echo "-----------------------"
    if ! visudo -cf "$tmp"; then
        echo "syntax check failed, nothing installed" >&2
        exit 1
    fi
    # visudo ownership check: file must be owned by root when installed
    sudo install -o root -g root -m 0440 "$tmp" "$TARGET"
    sudo visudo -c >/dev/null
    echo "installed: $TARGET"
    if as_owner sudo -n "$BROKER" capabilities >/dev/null 2>&1; then
        echo "verified: sudo -n $BROKER works for ${OWNER}"
    else
        echo "WARNING: rule installed but sudo -n still fails" >&2
        exit 1
    fi
}

remove_rule() {
    if [[ -f "$TARGET" ]]; then
        sudo rm -f "$TARGET"
        echo "removed: $TARGET"
    else
        echo "nothing to remove: $TARGET absent"
    fi
    if as_owner sudo -n "$BROKER" capabilities >/dev/null 2>&1; then
        echo "note: sudo -n still works for ${OWNER} (another rule or cached ticket)"
    fi
}

case "${1:-}" in
    "")        install_rule ;;
    --remove)  remove_rule ;;
    --check)   check_state ;;
    -h|--help) usage ;;
    *)         echo "unknown option: $1" >&2; usage; exit 2 ;;
esac
