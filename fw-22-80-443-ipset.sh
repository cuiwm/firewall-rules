#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 cuiwm
#
# Script:
#   fw-22-80-443-ipset.sh
#
# Description:
#   Baseline firewall setup using iptables + ipset.
#   Restricts inbound traffic and protects the following TCP ports:
#     - 22  (SSH)
#     - 80  (HTTP)
#     - 443 (HTTPS)
#
# Usage:
#   ./fw-22-80-443-ipset.sh install
#   ./fw-22-80-443-ipset.sh uninstall
#
# Requirements:
#   - bash >= 4.x
#   - iptables (iptables-nft or legacy)
#   - ipset
#
# Safety:
#   - Must be run as root
#   - This script modifies system firewall rules
#   - Incorrect usage may result in loss of network or SSH access
#
# Disclaimer:
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.


set -euo pipefail
# ---- Tunables ----
SSH_PORT="${SSH_PORT:-22}"
WEB_PORTS="${WEB_PORTS:-80,443}"

# SSH_MODE:
#   allowlist : allow SSH only from allow_admin (+ auto file)
#   public    : allow SSH from anywhere (not recommended)
SSH_MODE="${SSH_MODE:-allowlist}"

# public-web : allow 80/443 from anywhere
# origin-web : allow 80/443 ONLY from allow_web
WEB_MODE="${WEB_MODE:-public-web}"

SET_ALLOW_ADMIN="${SET_ALLOW_ADMIN:-allow_admin}"
SET_ALLOW_WEB="${SET_ALLOW_WEB:-allow_web}"
SET_DENY="${SET_DENY:-deny_src}"

IPSET_CONF="${IPSET_CONF:-/etc/ipset.conf}"
ALLOW_ADMIN_FILE="${ALLOW_ADMIN_FILE:-/etc/firewall/allow_admin.list}"
ALLOW_ADMIN_AUTO_FILE="${ALLOW_ADMIN_AUTO_FILE:-/etc/firewall/allow_admin.auto.list}"
ALLOW_WEB_FILE="${ALLOW_WEB_FILE:-/etc/firewall/allow_web.list}"
DENY_FILE="${DENY_FILE:-/etc/firewall/deny_src.list}"

CHAIN_BASE="IN-BASE"
CHAIN_SSH="IN-SSH"
CHAIN_WEB="IN-WEB"

# snapshot dir
SNAP_DIR="${SNAP_DIR:-/var/lib/fw-22-80-443}"
SNAP_LATEST_LINK="${SNAP_DIR}/latest"

# fail2ban integration (unbind on uninstall if enabled)
F2B_UNBIND="${F2B_UNBIND:-true}"
F2B_ACTION_FILE="${F2B_ACTION_FILE:-/etc/fail2ban/action.d/ipset-deny.conf}"
F2B_JAIL_LOCAL="${F2B_JAIL_LOCAL:-/etc/fail2ban/jail.local}"
F2B_JAIL_D_DIR="${F2B_JAIL_D_DIR:-/etc/fail2ban/jail.d}"

# ---- internal flags ----
DRY_RUN="false"

log(){ echo "[$(date +'%F %T')] $*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root"; }
cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

run() {
  # central execution wrapper for dry-run
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] $*"
  else
    eval "$@"
  fi
}

is_valid_ipv4_or_cidr() {
  local x="$1"
  [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]] || return 1
  # octet range check
  local ip="${x%%/*}"
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

is_valid_ip_or_cidr() {
  local x="$1"
  [[ -n "$x" ]] || return 1

  # Prefer python3 ipaddress for robust IPv4/IPv6/CIDR validation if available
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$x" >/dev/null 2>&1
import sys, ipaddress
s=sys.argv[1].strip()
# Accept IP or CIDR. strict=False allows host bits set.
ipaddress.ip_network(s, strict=False)
PY
    return $?
  fi

  # Fallback: IPv4 (and IPv4/CIDR) only
  is_valid_ipv4_or_cidr "$x"
}


ensure_pkgs() {
  if cmd_exists apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    run "apt-get update -y"
    run "apt-get install -y ipset iptables"
  elif cmd_exists dnf; then
    run "dnf install -y ipset iptables"
  elif cmd_exists yum; then
    run "yum install -y ipset iptables"
  else
    die "no supported package manager"
  fi
}

mkdir_lists() {
  run "mkdir -p /etc/firewall"
  run "touch '$ALLOW_ADMIN_FILE' '$ALLOW_ADMIN_AUTO_FILE' '$ALLOW_WEB_FILE' '$DENY_FILE'"
  run "chmod 0644 '$ALLOW_ADMIN_FILE' '$ALLOW_ADMIN_AUTO_FILE' '$ALLOW_WEB_FILE' '$DENY_FILE'"
}


# ---------------- Operator self-protection ----------------
# Auto-add the current operator's source IP to allow_admin.list
# to avoid locking yourself out when applying restrictive SSH rules.
#
# Preferred signal: SSH_CONNECTION (set by OpenSSH for remote sessions)
# Fallback: parse established TCP session to local SSH_PORT via ss.
detect_operator_src_ip() {
  # Preferred:
  #   SSH_CONNECTION: "<client_ip> <client_port> <server_ip> <server_port>"
  #   SSH_CLIENT    : "<client_ip> <client_port> <server_port>"
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    echo "${SSH_CONNECTION}" | awk '{print $1}'
    return 0
  fi
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    echo "${SSH_CLIENT}" | awk '{print $1}'
    return 0
  fi

  # Find the sshd pid that owns THIS shell session by walking the PPID chain.
  local pid ppid comm sshd_pid
  pid="$$"
  sshd_pid=""
  while [[ -n "$pid" && "$pid" != "1" ]]; do
    comm="$(ps -o comm= -p "$pid" 2>/dev/null | awk '{print $1}')"
    if [[ "$comm" == "sshd" ]]; then
      sshd_pid="$pid"
      break
    fi
    ppid="$(ps -o ppid= -p "$pid" 2>/dev/null | awk '{print $1}')"
    [[ -n "$ppid" ]] || break
    pid="$ppid"
  done

  # High-accuracy path: map sockets opened by that sshd instance -> find the one bound to local :$SSH_PORT
  # This avoids "first ESTAB" ambiguity on hosts with multiple SSH sessions.
  if [[ -n "$sshd_pid" && -r "/proc/${sshd_pid}/fd" ]] && command -v ss >/dev/null 2>&1; then
    # Collect socket inodes from /proc/<pid>/fd; symlink format: socket:[12345]
    local inodes
    inodes="$(
      ls -l "/proc/${sshd_pid}/fd" 2>/dev/null \
        | awk 'match($0, /socket:\[([0-9]+)\]/, m) { print m[1] }' \
        | sort -u
    )"

    if [[ -n "$inodes" ]]; then
      ss -Htnpie 2>/dev/null \
        | awk -v port=":${SSH_PORT}" -v inodes="$inodes" '
            BEGIN{
              n=split(inodes, arr, "\n");
              for(i=1;i<=n;i++){ if(arr[i]!="") want[arr[i]]=1; }
            }
            $1=="ESTAB" {
              local=$4; peer=$5;

              # Must match local ssh port
              if (local !~ (port "$")) next;

              # Must have inode and belong to this sshd
              if (match($0, /ino:([0-9]+)/, m)==0) next;
              ino=m[1];
              if (!(ino in want)) next;

              # Parse peer formats
              if (peer ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) {
                gsub(/^\[/, "", peer); gsub(/\]$/, "", peer);
                sub(/:[0-9]+$/, "", peer);
                print peer; exit;
              }
              if (peer ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
                split(peer, a, ":"); host=a[1];
                if(host!="127.0.0.1"){ print host; exit; }
              }
              # Fallback for IPv6 without brackets: remove last ":<port>"
              if (peer ~ /:[0-9]+$/) {
                sub(/:[0-9]+$/, "", peer);
                if(peer!="::1"){ print peer; exit; }
              }
            }'
      return 0
    fi
  fi

  # Best-effort fallback: first ESTAB to local :$SSH_PORT (IPv4 or bracketed IPv6)
  if command -v ss >/dev/null 2>&1; then
    ss -Htnp "sport = :${SSH_PORT}" 2>/dev/null \
      | awk '
          $1=="ESTAB" {
            peer=$5
            if (peer ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) {
              gsub(/^\[/, "", peer); gsub(/\]$/, "", peer)
              sub(/:[0-9]+$/, "", peer)
              if(peer!="::1"){ print peer; exit }
            } else if (peer ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
              split(peer, a, ":"); host=a[1]
              if(host!="127.0.0.1"){ print host; exit }
            } else if (peer ~ /:[0-9]+$/) {
              sub(/:[0-9]+$/, "", peer)
              if(peer!="::1"){ print peer; exit }
            }
          }'
    return 0
  fi

  echo ""
}

auto_whitelist_operator() {
  local ip
  ip="$(detect_operator_src_ip | head -n1 | xargs || true)"
  [[ -n "$ip" ]] || { log "Operator src IP not detected; skip auto-whitelist"; return 0; }
  if ! is_valid_ip_or_cidr "$ip"; then
    log "WARN: operator src IP looks invalid; skip auto-whitelist: $ip"
    return 0
  fi

  if [[ "$SSH_MODE" != "allowlist" ]]; then
    log "SSH_MODE=$SSH_MODE (not allowlist); skip auto-whitelist"
    return 0
  fi

  # Ensure file exists
  run "mkdir -p '$(dirname "$ALLOW_ADMIN_AUTO_FILE")'"
  run "touch '$ALLOW_ADMIN_FILE'"
  run "chmod 0644 '$ALLOW_ADMIN_FILE'"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] ensure operator IP in allowlist: $ip -> $ALLOW_ADMIN_AUTO_FILE"
    return 0
  fi

  # Exact-line match (ignoring trailing comments/spaces)
  if grep -Eq "^[[:space:]]*${ip//./\\.}([[:space:]]*(#.*)?)?$" "$ALLOW_ADMIN_AUTO_FILE"; then
    log "Operator IP already in auto-allowlist: $ip"
  else
    echo "$ip  # auto-added by fw-22-80-443-ipset.sh" >> "$ALLOW_ADMIN_AUTO_FILE"
    log "Auto-whitelisted operator IP: $ip"
  fi
}

read_list() {
  local f="$1"
  awk '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*$/ {next}
    {
      # strip inline comments: "1.2.3.4  # comment" -> "1.2.3.4"
      sub(/[[:space:]]*#.*/, "", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      if ($0 != "") print $0
    }
' "$f"
}

read_list_multi() {
  # Merge multiple list files into a single stream (deduped).
  # Usage: read_list_multi file1 file2 ...
  # Notes:
  # - Keeps only non-empty, non-comment lines
  # - Deduplicates exact strings
  local tmp
  tmp="$(mktemp)"
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    read_list "$f" >> "$tmp"
  done
  sort -u "$tmp"
  rm -f "$tmp"
}

ensure_ipset() {
  local name="$1" type="$2"
  if ! ipset list -n 2>/dev/null | grep -qx "$name"; then
    run "ipset create '$name' '$type' family inet hashsize 1024 maxelem 65536"
    log "ipset created: $name ($type)"
  fi
}

sync_ipset_from_file() {
  local setname="$1" file="$2"
  run "ipset flush '$setname' || true"
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    if ! is_valid_ip_or_cidr "$ip"; then
      log "WARN: invalid IP/CIDR skipped in $file: $ip"
      continue
    fi
    run "ipset add '$setname' '$ip' -exist"
  done < <(read_list "$file" || true)

  if [[ "$DRY_RUN" == "false" ]]; then
    local n; n="$(ipset list "$setname" 2>/dev/null | awk '/Number of entries:/{print $4}')"
    log "ipset sync: $setname entries=${n:-0}"
  else
    log "ipset sync (dry-run): $setname from $file"
  fi
}

sync_allow_admin_ipset() {
  # Merge human-managed allowlist + auto-generated allowlist
  # into the allow_admin ipset.
  local tmp
  tmp="$(mktemp)"
  read_list_multi "$ALLOW_ADMIN_FILE" "$ALLOW_ADMIN_AUTO_FILE" > "$tmp" || true

  run "ipset flush '$SET_ALLOW_ADMIN' || true"
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    if ! is_valid_ip_or_cidr "$ip"; then
      log "WARN: invalid IP/CIDR skipped in merged allow_admin lists: $ip"
      continue
    fi
    run "ipset add '$SET_ALLOW_ADMIN' '$ip' -exist"
  done < "$tmp"

  rm -f "$tmp"

  if [[ "$DRY_RUN" == "false" ]]; then
    local n; n="$(ipset list "$SET_ALLOW_ADMIN" 2>/dev/null | awk '/Number of entries:/{print $4}')"
    log "ipset sync: $SET_ALLOW_ADMIN entries=${n:-0} (merged: allow_admin.list + allow_admin.auto.list)"
  else
    log "ipset sync (dry-run): $SET_ALLOW_ADMIN (merged allow_admin.list + allow_admin.auto.list)"
  fi
}

iptables_chain_exists() { iptables -S 2>/dev/null | grep -qE "^-N $1\$"; }

ensure_chain() {
  local c="$1"
  if ! iptables_chain_exists "$c"; then
    run "iptables -N '$c'"
  fi
  run "iptables -F '$c'"
}

ensure_jump_input() {
  local c="$1"
  if ! iptables -C INPUT -j "$c" 2>/dev/null; then
    run "iptables -I INPUT 1 -j '$c'"
  fi
}

apply_rules() {
  ensure_chain "$CHAIN_BASE"
  ensure_chain "$CHAIN_SSH"
  ensure_chain "$CHAIN_WEB"

  # BASE
  run "iptables -A '$CHAIN_BASE' -i lo -j ACCEPT"
  run "iptables -A '$CHAIN_BASE' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
  run "iptables -A '$CHAIN_BASE' -m set --match-set '$SET_DENY' src -j DROP"

  run "iptables -A '$CHAIN_BASE' -p tcp --dport '$SSH_PORT' -j '$CHAIN_SSH'"
  run "iptables -A '$CHAIN_BASE' -p tcp -m multiport --dports '$WEB_PORTS' -j '$CHAIN_WEB'"

  run "iptables -A '$CHAIN_BASE' -j DROP"

  # SSH
  case "$SSH_MODE" in
    allowlist)
      run "iptables -A '$CHAIN_SSH' -m set --match-set '$SET_ALLOW_ADMIN' src -j ACCEPT"
      run "iptables -A '$CHAIN_SSH' -j DROP"
      ;;
    public)
      run "iptables -A '$CHAIN_SSH' -j ACCEPT"
      ;;
    *)
      die "SSH_MODE must be allowlist or public"
      ;;
  esac

  # WEB
  case "$WEB_MODE" in
    public-web)
      run "iptables -A '$CHAIN_WEB' -j ACCEPT"
      ;;
    origin-web)
      run "iptables -A '$CHAIN_WEB' -m set --match-set '$SET_ALLOW_WEB' src -j ACCEPT"
      run "iptables -A '$CHAIN_WEB' -j DROP"
      ;;
    *)
      die "WEB_MODE must be public-web or origin-web"
      ;;
  esac

  ensure_jump_input "$CHAIN_BASE"
  log "iptables rules applied (managed chains only)"
}

persist_ipset() {
  # save current ipset state for restore on boot
  run "ipset save > '$IPSET_CONF'"
  run "chmod 0644 '$IPSET_CONF'"

  run "cat > /etc/systemd/system/ipset-restore.service <<'EOF'
[Unit]
Description=Restore ipset rules
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -exist -f /etc/ipset.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF"
  run "systemctl daemon-reload"
  run "systemctl enable --now ipset-restore.service"
  log "ipset persistence enabled (ipset-restore.service)"
}

# ---------------- Snapshot / Rollback ----------------

snapshot() {
  need_root
  run "mkdir -p '$SNAP_DIR'"
  local ts; ts="$(date +'%Y%m%d-%H%M%S')"
  local out="${SNAP_DIR}/${ts}"
  run "mkdir -p '$out'"

  run "iptables-save > '${out}/iptables-save.txt'"
  run "ipset save > '${out}/ipset-save.txt' || true"

  run "cat > '${out}/meta.env' <<EOF
TS=${ts}
SSH_PORT=${SSH_PORT}
WEB_PORTS=${WEB_PORTS}
WEB_MODE=${WEB_MODE}
SET_ALLOW_ADMIN=${SET_ALLOW_ADMIN}
SET_ALLOW_WEB=${SET_ALLOW_WEB}
SET_DENY=${SET_DENY}
EOF"

  if [[ "$DRY_RUN" == "false" ]]; then
    ln -sfn "$out" "$SNAP_LATEST_LINK"
  else
    echo "[dry-run] ln -sfn '$out' '$SNAP_LATEST_LINK'"
  fi

  log "Snapshot saved: $out"
}

rollback() {
  need_root
  local target="${1:-$SNAP_LATEST_LINK}"
  [[ -e "$target" ]] || die "snapshot not found: $target"

  run "iptables-restore < '${target}/iptables-save.txt'"
  run "ipset restore -exist < '${target}/ipset-save.txt' || true"

  run "ipset save > '$IPSET_CONF' || true"
  if [[ -f /etc/systemd/system/ipset-restore.service ]]; then
    run "systemctl daemon-reload"
    run "systemctl enable --now ipset-restore.service || true"
  fi

  log "Rollback done from: $target"
}

list_snapshots() {
  need_root
  if [[ -d "$SNAP_DIR" ]]; then
    ls -1 "$SNAP_DIR" | grep -E '^[0-9]{8}-[0-9]{6}$' || true
  fi
}

# ---------------- Fail2ban unbind ----------------

f2b_unbind() {
  [[ "$F2B_UNBIND" == "true" ]] || { log "Fail2ban unbind disabled"; return 0; }

  if [[ -f "$F2B_ACTION_FILE" ]]; then
    run "rm -f '$F2B_ACTION_FILE'"
    log "Removed fail2ban action: $F2B_ACTION_FILE"
  fi

  if [[ -f "$F2B_JAIL_LOCAL" ]]; then
    run "cp -a '$F2B_JAIL_LOCAL' '${F2B_JAIL_LOCAL}.bak.$(date +%Y%m%d-%H%M%S)'"
    run "grep -n 'ipset-deny' '$F2B_JAIL_LOCAL' >/dev/null 2>&1 && \
         sed -i '/ipset-deny/d' '$F2B_JAIL_LOCAL' || true"
    log "Cleaned ipset-deny references in $F2B_JAIL_LOCAL (if any)"
  fi

  if [[ -d "$F2B_JAIL_D_DIR" ]]; then
    local f
    for f in "$F2B_JAIL_D_DIR"/*.conf; do
      [[ -f "$f" ]] || continue
      run "grep -n 'ipset-deny' '$f' >/dev/null 2>&1 && \
           cp -a '$f' '${f}.bak.$(date +%Y%m%d-%H%M%S)' && \
           sed -i '/ipset-deny/d' '$f' || true"
    done
    log "Cleaned ipset-deny references in $F2B_JAIL_D_DIR/*.conf (if any)"
  fi

  if systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban.service'; then
    run "systemctl restart fail2ban || true"
    log "Restarted fail2ban (best-effort)"
  fi
}

# ---------------- Uninstall ----------------

uninstall() {
  need_root
  auto_whitelist_operator
  log "Start uninstall firewall baseline (iptables + ipset)"
  snapshot

  if iptables -C INPUT -j "$CHAIN_BASE" 2>/dev/null; then
    run "iptables -D INPUT -j '$CHAIN_BASE'"
    log "Removed jump: INPUT -> $CHAIN_BASE"
  else
    log "Jump INPUT -> $CHAIN_BASE not present"
  fi

  for c in "$CHAIN_WEB" "$CHAIN_SSH" "$CHAIN_BASE"; do
    if iptables_chain_exists "$c"; then
      run "iptables -F '$c'"
      run "iptables -X '$c'"
      log "Deleted chain: $c"
    else
      log "Chain not present: $c"
    fi
  done

  if systemctl list-unit-files | grep -q '^ipset-restore.service'; then
    run "systemctl disable --now ipset-restore.service || true"
    run "rm -f /etc/systemd/system/ipset-restore.service"
    run "systemctl daemon-reload"
    log "Removed ipset-restore.service"
  fi
  if [[ -f "$IPSET_CONF" ]]; then
    run "rm -f '$IPSET_CONF'"
    log "Removed $IPSET_CONF"
  fi

  for s in "$SET_ALLOW_ADMIN" "$SET_ALLOW_WEB" "$SET_DENY"; do
    if ipset list -n 2>/dev/null | grep -qx "$s"; then
      run "ipset flush '$s' || true"
      run "ipset destroy '$s'"
      log "Destroyed ipset: $s"
    else
      log "ipset not present: $s"
    fi
  done

  f2b_unbind

  log "UNINSTALL COMPLETE"
  log "NOTE:"
  log " - iptables default policies untouched"
  log " - /etc/firewall/*.list preserved"
  log " - packages NOT removed"
}

# ---------------- Other commands ----------------

status() {
  need_root
  echo "== INPUT jump =="
  iptables -S INPUT | sed -n '1,120p' || true
  echo
  echo "== chains =="
  iptables -S "$CHAIN_BASE" 2>/dev/null || true
  iptables -S "$CHAIN_SSH" 2>/dev/null || true
  iptables -S "$CHAIN_WEB" 2>/dev/null || true
  echo
  echo "== ipset =="
  ipset list "$SET_ALLOW_ADMIN" 2>/dev/null | sed -n '1,80p' || true
  ipset list "$SET_ALLOW_WEB" 2>/dev/null | sed -n '1,80p' || true
  ipset list "$SET_DENY" 2>/dev/null | sed -n '1,80p' || true
  echo
  echo "== snapshots =="
  list_snapshots || true
}

install() {
  need_root
  ensure_pkgs
  mkdir_lists
  snapshot

  ensure_ipset "$SET_ALLOW_ADMIN" "hash:net"
  ensure_ipset "$SET_ALLOW_WEB" "hash:net"
  ensure_ipset "$SET_DENY" "hash:net"

  sync_allow_admin_ipset
  sync_ipset_from_file "$SET_ALLOW_WEB" "$ALLOW_WEB_FILE"
  sync_ipset_from_file "$SET_DENY" "$DENY_FILE"

  apply_rules
  persist_ipset
  snapshot

  log "DONE."
  log "Edit lists:"
  log "  admin allow: $ALLOW_ADMIN_FILE"
  log "  web allow  : $ALLOW_WEB_FILE (used only in WEB_MODE=origin-web)"
  log "  deny list  : $DENY_FILE"
  log "Then run: sudo $0 update"
}

update() {
  need_root
  snapshot
  auto_whitelist_operator

  sync_allow_admin_ipset
  sync_ipset_from_file "$SET_ALLOW_WEB" "$ALLOW_WEB_FILE"
  sync_ipset_from_file "$SET_DENY" "$DENY_FILE"

  apply_rules
  persist_ipset
  snapshot

  log "UPDATED."
}

usage() {
  cat <<EOF
Usage:
  sudo $0 [--dry-run] install
  sudo $0 [--dry-run] update
  sudo $0 [--dry-run] uninstall
  sudo $0 status
  sudo $0 snapshot
  sudo $0 list-snapshots
  sudo $0 rollback [<snapshot_dir_or_latest_link>]

Env:
  SSH_PORT=22
  SSH_MODE=allowlist|public
  WEB_MODE=public-web|origin-web
  WEB_PORTS=80,443
  SNAP_DIR=/var/lib/fw-22-80-443
  ALLOW_ADMIN_AUTO_FILE=/etc/firewall/allow_admin.auto.list

Notes:
  - List parsing strips inline comments (# ...).
  - IP/CIDR validation prefers python3 ipaddress if available; falls back to IPv4-only validation.
  F2B_UNBIND=true|false
EOF
}

parse_args() {
  local argv=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN="true"; shift ;;
      *) argv+=("$1"); shift ;;
    esac
  done
  echo "${argv[@]:-}"
}

main() {
  local args; args="$(parse_args "$@")"
  # shellcheck disable=SC2206
  set -- $args

  local cmd="${1:-}"
  case "$cmd" in
    install) install ;;
    update) update ;;
    uninstall) uninstall ;;
    status) status ;;
    snapshot) snapshot ;;
    list-snapshots) list_snapshots ;;
    rollback) rollback "${2:-$SNAP_LATEST_LINK}" ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
