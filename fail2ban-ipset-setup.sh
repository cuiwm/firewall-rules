#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 cuiwm
#
# Script:
#   fail2ban-ipset-setup.sh
#
# Description:
#   Configure fail2ban to use ipset-based banning
#   instead of nftables native sets.
#
# Supported Modes:
#   - install
#   - uninstall
#   - bootfix
#
# Requirements:
#   - fail2ban >= 0.11
#   - ipset
#   - iptables-nft or legacy iptables
#
# Safety:
#   - Must be run as root
#   - Modifies fail2ban actions and firewall behavior
#
# Disclaimer:
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

set -euo pipefail

# ============================================================
# Fail2ban + ipset (deny_src) one-click setup
# Cooperates with fw-22-80-443-ipset.sh (iptables drops deny_src early)
#
# Key properties:
#   - Fail2ban NEVER inserts iptables rules (ipset-only action)
#   - Optional TTL alignment (ipset entry timeout ~= bantime)
#   - Tagged audit log for bans/unbans (per jail)
#   - Guard (systemd ExecStartPre) blocks unsafe actions (iptables/nftables/firewalld/ufw)
#
# Commands:
#   install            Install + configure + enable sshd(ipset)
#   enable-nginx       Enable nginx jails (nginx-http-auth + nginx-badbots) -> ipset deny_src
#   enable-recidive    Enable recidive jail -> ipset deny_src
#   selfcheck          Evidence pack + guard audit
#   status             Show fail2ban + ipset + tag log (read-only)
#   disable-iptables   Hard-disable built-in iptables/nftables/firewalld/ufw actions (optional)
#   uninstall          Remove only configs created by this script
#
# Examples:
#   sudo ./fail2ban-ipset-setup.sh install
#   sudo ./fail2ban-ipset-setup.sh enable-nginx
#   sudo ./fail2ban-ipset-setup.sh enable-recidive
#   sudo ./fail2ban-ipset-setup.sh selfcheck
# ============================================================

# ---- Tunables (override via env) ----
DENY_SET="${DENY_SET:-deny_src}"          # must match fw script SET_DENY
SSH_PORT="${SSH_PORT:-22}"

MAXRETRY="${MAXRETRY:-5}"
FINDTIME="${FINDTIME:-10m}"
BANTIME="${BANTIME:-1h}"

BACKEND="${BACKEND:-systemd}"            # systemd recommended

# TTL alignment
USE_IPSET_TIMEOUT="${USE_IPSET_TIMEOUT:-true}"

# Tag/audit trail log
TAG_LOG="${TAG_LOG:-/var/log/fail2ban-ipset-tags.log}"

# Guard behavior
GUARD_BLOCK="${GUARD_BLOCK:-true}"        # if true: ExecStartPre fails when unsafe action found

# Nginx specifics
# If BACKEND=systemd, fail2ban will read journald; otherwise it needs logpath.
NGINX_LOG_CANDIDATES=(
  "/var/log/nginx/error.log"
  "/var/log/nginx/access.log"
)

log(){ echo "[$(date +'%F %T')] $*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root"; }
cmd(){ command -v "$1" >/dev/null 2>&1; }

parse_duration_to_seconds() {
  local s="${1}"
  if [[ "$s" =~ ^[0-9]+$ ]]; then echo "$s"; return 0; fi
  if [[ "$s" =~ ^([0-9]+)([smhd])$ ]]; then
    local n="${BASH_REMATCH[1]}"; local u="${BASH_REMATCH[2]}"
    case "$u" in
      s) echo "$n" ;;
      m) echo $((n*60)) ;;
      h) echo $((n*3600)) ;;
      d) echo $((n*86400)) ;;
    esac
    return 0
  fi
  die "Cannot parse duration: $s (use e.g. 10m/1h/2d or seconds)"
}

install_pkgs() {
  if cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y fail2ban ipset
  elif cmd dnf; then
    dnf install -y fail2ban ipset
  elif cmd yum; then
    yum install -y fail2ban ipset
  else
    die "unsupported package manager"
  fi
}

ensure_ipset() {
  local bantime_sec; bantime_sec="$(parse_duration_to_seconds "$BANTIME")"

  # Create deny set if missing. Keep family inet (IPv4) to match fw script.
  if ! ipset list -n 2>/dev/null | grep -qx "$DENY_SET"; then
    if [[ "$USE_IPSET_TIMEOUT" == "true" ]]; then
      ipset create "$DENY_SET" hash:ip family inet hashsize 1024 maxelem 65536 timeout "$bantime_sec"
      log "Created ipset: $DENY_SET (timeout=${bantime_sec}s)"
    else
      ipset create "$DENY_SET" hash:ip family inet hashsize 1024 maxelem 65536
      log "Created ipset: $DENY_SET"
    fi
  else
    log "ipset exists: $DENY_SET (leave as-is)"
  fi
}

ipset_has_timeout() {
  local set="${1}"
  # Returns 0 if set header indicates timeout support, else 1
  ipset list "$set" 2>/dev/null | grep -qE '^Header:.*\btimeout\b'
}

backup_ipset_set() {
  local set="${1}"
  local dir="/etc/firewall/ipset-backups"
  mkdir -p "$dir"
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  local out="${dir}/${set}.${ts}.save"
  ipset save "$set" > "$out"
  chmod 0600 "$out"
  echo "$out"
}

export_ipset_members() {
  local set="${1}"
  # Output members, one per line
  # NOTE: awk keyword 'in' cannot be used as a variable name.
  ipset list "$set" 2>/dev/null | awk '
    /^Members:/ {m=1; next}
    m==1 && NF>=1 {print $1}
  '
}

upgrade_ipset_timeout() {
  local set="${1}"
  local timeout_sec="${2}"
  local tmp_new="${set}__new"

  if ! ipset list -n 2>/dev/null | grep -qx "$set"; then
    die "ipset set not found: $set"
  fi

  if ipset_has_timeout "$set"; then
    log "OK: ipset set already supports timeout: $set"
    return 0
  fi

  log "Upgrading ipset set to support timeout: $set (timeout=${timeout_sec}s)"
  local backup; backup="$(backup_ipset_set "$set")"
  log "Backup saved: $backup"

  # Collect members
  local members_file; members_file="$(mktemp)"
  export_ipset_members "$set" > "$members_file" || true
  local count; count="$(wc -l < "$members_file" | tr -d ' ')"

  # Create new set with timeout
  # Keep hash:net + family inet to match fw script, so iptables match set remains valid.
  ipset destroy "$tmp_new" 2>/dev/null || true
  ipset create "$tmp_new" hash:net family inet hashsize 1024 maxelem 65536 timeout "$timeout_sec"

  # Import members (use default set timeout)
  if [[ "$count" != "0" ]]; then
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      ipset add "$tmp_new" "$ip" -exist || true
    done < "$members_file"
  fi
  rm -f "$members_file"

  # Atomic swap
  ipset swap "$tmp_new" "$set"
  ipset destroy "$tmp_new" 2>/dev/null || true

  log "Upgrade done: $set now supports timeout."
  log "Rollback command:"
  log "  $0 rollback-timeout $backup"
}

rollback_ipset_from_backup() {
  local backup_file="${1}"
  [[ -f "$backup_file" ]] || die "backup file not found: $backup_file"

  # Restore requires sets not to conflict; easiest is flush+destroy target then restore.
  log "Rolling back ipset from backup: $backup_file"
  # Parse set names from save file (lines starting with 'create ')
  local sets
  sets="$(awk '/^create /{print $2}' "$backup_file" | sort -u)"
  # Destroy any existing sets present in backup file, in reverse order is fine for independent sets.
  while IFS= read -r s; do
    [[ -n "$s" ]] || continue
    ipset destroy "$s" 2>/dev/null || true
  done <<< "$sets"

  ipset restore < "$backup_file"
  log "Rollback restore completed."
}

write_action() {
  mkdir -p /etc/fail2ban/action.d
  cat > /etc/fail2ban/action.d/ipset-deny.conf <<'EOF'
# Fail2ban action: ban/unban by writing IPs into an ipset set.
# Usage in jail:
#   action = ipset-deny[set=deny_src, bantime_sec=3600,taglog=/var/log/fail2ban-ipset-tags.log]
#
# Notes:
#   - Compatible with sets created by fw-22-80-443-ipset.sh (often hash:net).
#   - If the target set does NOT support timeouts, we automatically fall back to plain add (no -timeout).
#   - Fail2ban config treats '%' specially. Use '%%' for literal percent.

[Init]
allowipv6 = auto

[Definition]
allowipv6 = auto

actionstart =
  /bin/bash -c '\
    IPSET="$(command -v ipset || true)"; \
    [ -n "$IPSET" ] || IPSET="/usr/sbin/ipset"; \
    "$IPSET" create <set> hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || \
    "$IPSET" create <set> hash:ip  family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true \
  '

actionstop =
  true

actioncheck =
  /bin/bash -c '\
    IPSET="$(command -v ipset || true)"; \
    [ -n "$IPSET" ] || IPSET="/usr/sbin/ipset"; \
    "$IPSET" list -n 2>/dev/null | /bin/grep -qx <set> \
  '

actionban =
  /bin/bash -c '\
    IPSET="$(command -v ipset || true)"; \
    [ -n "$IPSET" ] || IPSET="/usr/sbin/ipset"; \
    used_timeout=false; \
    rc=0; \
    if [ -n "<bantime_sec>" ]; then \
      # ipset CLI uses "timeout <sec>" (NOT "-timeout")
      if "$IPSET" add "<set>" "<ip>" timeout "<bantime_sec>" -exist; then \
        used_timeout=true; \
        rc=0; \
      else \
        rc=$?; \
        echo "[WARN] ipset add with timeout failed rc=$rc; retry without timeout" >&2; \
        if "$IPSET" add "<set>" "<ip>" -exist; then \
          rc=0; \
        else \
          rc=$?; \
        fi; \
      fi; \
    else \
      if "$IPSET" add "<set>" "<ip>" -exist; then rc=0; else rc=$?; fi; \
    fi; \
    ts="$(date "+%%F %%T")"; \
    if [ "$rc" -ne 0 ]; then \
      echo "[$ts] jail=<name> ban FAILED ip=<ip> set=<set> bantime_sec=<bantime_sec> timeout_used=$used_timeout rc=$rc" >> "<taglog>"; \
      exit "$rc"; \
    fi; \
    echo "[$ts] jail=<name> ban ip=<ip> set=<set> bantime_sec=<bantime_sec> timeout_used=$used_timeout" >> "<taglog>" \
  '

actionunban =
  /bin/bash -c '\
    IPSET="$(command -v ipset || true)"; \
    [ -n "$IPSET" ] || IPSET="/usr/sbin/ipset"; \
    "$IPSET" del "<set>" "<ip>" 2>/dev/null || true; \
    ts="$(date "+%%F %%T")"; \
    echo "[$ts] jail=<name> unban ip=<ip> set=<set>" >> "<taglog>" \
  '
EOF
  chmod 0644 /etc/fail2ban/action.d/ipset-deny.conf
  touch "$TAG_LOG"
  chmod 0644 "$TAG_LOG"
  log "Wrote action: /etc/fail2ban/action.d/ipset-deny.conf"
  log "Tag log: $TAG_LOG"
}

write_defaults() {
  mkdir -p /etc/fail2ban/jail.d
  # Force Fail2ban to use ipset deny_src (NOT nftables sets), even if distro defaults change.
  cat > /etc/fail2ban/jail.d/00-ipset-deny-defaults.local <<EOF
[DEFAULT]
# Override distro default banaction (often nftables-multiport) to our ipset-based action.
# Many jails rely on banaction; we keep it aligned with our custom action.
banaction = ipset-deny[set=${DENY_SET},bantime_sec=$(parse_duration_to_seconds "${BANTIME}"),taglog=${TAG_LOG}]
banaction_allports = ipset-deny[set=${DENY_SET},bantime_sec=$(parse_duration_to_seconds "${BANTIME}"),taglog=${TAG_LOG}]
EOF

  cat > /etc/fail2ban/jail.d/00-ipset-default.conf <<EOF
[DEFAULT]
banaction = ipset-deny
banaction_allports = ipset-deny
action = ipset-deny[set=$DENY_SET,bantime_sec=$(parse_duration_to_seconds "$BANTIME"),taglog=$TAG_LOG]
EOF
  chmod 0644 /etc/fail2ban/jail.d/00-ipset-default.conf
  log "Wrote defaults: /etc/fail2ban/jail.d/00-ipset-default.conf"
}

write_guard() {
  mkdir -p /usr/local/sbin
  cat > /usr/local/sbin/fail2ban-action-audit.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
BAD_RE='(iptables|nftables|firewallcmd|ufw|shorewall)'
if ! command -v fail2ban-client >/dev/null 2>&1; then exit 0; fi
cfg="$(fail2ban-client -d 2>/dev/null || true)"
bad="$(echo "$cfg" | grep -E '^[[:space:]]*action[[:space:]]*=' | grep -Ei "$BAD_RE" || true)"
if [[ -n "$bad" ]]; then
  echo "FAIL: unsafe fail2ban actions found (may touch firewall):" >&2
  echo "$bad" >&2
  exit 2
fi
exit 0
EOF
  chmod 0755 /usr/local/sbin/fail2ban-action-audit.sh
  log "Wrote guard: /usr/local/sbin/fail2ban-action-audit.sh"

  if cmd systemctl; then
    mkdir -p /etc/systemd/system/fail2ban.service.d
    if [[ "$GUARD_BLOCK" == "true" ]]; then
      cat > /etc/systemd/system/fail2ban.service.d/10-no-iptables.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/sbin/fail2ban-action-audit.sh
EOF
      log "Enabled guard via systemd ExecStartPre (BLOCKING)"
    else
      cat > /etc/systemd/system/fail2ban.service.d/10-no-iptables.conf <<'EOF'
[Service]
ExecStartPre=/bin/bash -c '/usr/local/sbin/fail2ban-action-audit.sh || true'
EOF
      log "Enabled guard via systemd ExecStartPre (non-blocking)"
    fi
    
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "fw-22-80-443-ipset.service"; then
    cat > "${dropdir}/21-after-fw.conf" <<'EOF'
[Unit]
Wants=fw-22-80-443-ipset.service
After=fw-22-80-443-ipset.service
EOF
    log "Detected fw-22-80-443-ipset.service; installed ordering drop-in: ${dropdir}/21-after-fw.conf"
  fi

systemctl daemon-reload
  fi
}

restart_fail2ban() {
  if cmd systemctl; then
    systemctl enable --now fail2ban || true
    systemctl restart fail2ban
  else
    service fail2ban restart || true
  fi
  log "fail2ban restarted"
}

# ---------------- jails ----------------

write_jail_sshd() {
  mkdir -p /etc/fail2ban/jail.d

  local bantime_sec; bantime_sec="$(parse_duration_to_seconds "$BANTIME")"

  # Prefer file logs when available (most reliable across distros)
  local sshlog; sshlog="$(detect_ssh_logpath)"
  local backend="$BACKEND"

  # If BACKEND=systemd but ssh logs are file-based (common), you can still use auto+logpath.
  # Using systemd without proper journalmatch (ssh.service vs sshd.service) is a common pitfall.
  if [[ "$backend" == "systemd" && -n "$sshlog" ]]; then
    log "INFO: BACKEND=systemd requested, but detected ssh auth log at $sshlog; using backend=auto + logpath for portability"
    backend="auto"
  fi

  cat > /etc/fail2ban/jail.d/sshd-ipset.conf <<EOF
[sshd]
enabled = true
port = $SSH_PORT

# For portability, we default to file backend when log exists.
backend = $backend
action = ipset-deny[set=$DENY_SET,bantime_sec=$bantime_sec,taglog=$TAG_LOG]

maxretry = $MAXRETRY
findtime = $FINDTIME
bantime  = $BANTIME
EOF

  if [[ "$backend" != "systemd" && -n "$sshlog" ]]; then
    echo "logpath = $sshlog" >> /etc/fail2ban/jail.d/sshd-ipset.conf
  fi

  if [[ "$backend" == "systemd" ]]; then
    # Explicit journalmatch for both unit names (Ubuntu uses ssh.service; others use sshd.service)
    cat >> /etc/fail2ban/jail.d/sshd-ipset.conf <<'EOF'
journalmatch = _SYSTEMD_UNIT=ssh.service _COMM=sshd + _SYSTEMD_UNIT=sshd.service _COMM=sshd
EOF
  fi

  chmod 0644 /etc/fail2ban/jail.d/sshd-ipset.conf
  log "Wrote jail: /etc/fail2ban/jail.d/sshd-ipset.conf"
}

detect_nginx_logpath() {
  local f
  for f in "${NGINX_LOG_CANDIDATES[@]}"; do
    if [[ -f "$f" ]]; then echo "$f"; return 0; fi
  done
  echo ""
}

detect_ssh_logpath() {
  # Ubuntu/Debian: /var/log/auth.log
  # RHEL/CentOS:   /var/log/secure
  if [[ -f /var/log/auth.log ]]; then
    echo "/var/log/auth.log"
    return 0
  fi
  if [[ -f /var/log/secure ]]; then
    echo "/var/log/secure"
    return 0
  fi
  echo ""
}

write_jail_nginx() {
  mkdir -p /etc/fail2ban/jail.d

  local have_httpauth="false" have_badbots="false"
  [[ -f /etc/fail2ban/filter.d/nginx-http-auth.conf ]] && have_httpauth="true"
  [[ -f /etc/fail2ban/filter.d/nginx-badbots.conf ]] && have_badbots="true"

  local logpath=""
  if [[ "$BACKEND" != "systemd" ]]; then
    logpath="$(detect_nginx_logpath)"
    [[ -n "$logpath" ]] || log "WARN: BACKEND=$BACKEND and no nginx log found; set logpath manually in /etc/fail2ban/jail.d/nginx-ipset.conf"
  fi

  cat > /etc/fail2ban/jail.d/nginx-ipset.conf <<EOF
# Nginx jails -> ipset blacklist ($DENY_SET)

[nginx-http-auth]
enabled = ${have_httpauth}
backend = $BACKEND
action = ipset-deny[set=$DENY_SET,bantime_sec=$(parse_duration_to_seconds "$BANTIME"),taglog=$TAG_LOG]
EOF
  if [[ "$BACKEND" != "systemd" && -n "$logpath" ]]; then
    echo "logpath = $logpath" >> /etc/fail2ban/jail.d/nginx-ipset.conf
  fi
  cat >> /etc/fail2ban/jail.d/nginx-ipset.conf <<EOF
maxretry = $MAXRETRY
findtime = $FINDTIME
bantime  = $BANTIME

[nginx-badbots]
enabled = ${have_badbots}
backend = $BACKEND
action = ipset-deny[set=$DENY_SET,bantime_sec=$(parse_duration_to_seconds "$BANTIME"),taglog=$TAG_LOG]
EOF
  if [[ "$BACKEND" != "systemd" && -n "$logpath" ]]; then
    echo "logpath = $logpath" >> /etc/fail2ban/jail.d/nginx-ipset.conf
  fi
  cat >> /etc/fail2ban/jail.d/nginx-ipset.conf <<EOF
maxretry = $MAXRETRY
findtime = $FINDTIME
bantime  = $BANTIME
EOF

  chmod 0644 /etc/fail2ban/jail.d/nginx-ipset.conf

  if [[ "$have_httpauth" != "true" || "$have_badbots" != "true" ]]; then
    log "NOTE: nginx filters present? http-auth=$have_httpauth badbots=$have_badbots"
    log "      If missing, add filters under /etc/fail2ban/filter.d/"
  fi

  log "Wrote nginx jails: /etc/fail2ban/jail.d/nginx-ipset.conf"
}


install_filter_nginx_scan() {
  mkdir -p /etc/fail2ban/filter.d
  cat > /etc/fail2ban/filter.d/nginx-scan.conf <<'EOF'
# Custom filter: Nginx common scanner / probe patterns from access.log
#
# Matches:
#  - WordPress probes (wp-login.php, xmlrpc.php)
#  - phpMyAdmin probes
#  - .env / config / backup files
#  - common exploit / traversal patterns
#
# Tune/extend as needed.

[Definition]
# Default nginx access log includes: <host> - <user> [date] "<method> <url> <proto>" <status> <bytes> ...
# We match the request line part.

failregex = ^<HOST> - .*"(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH) (/(wp-login\.php|xmlrpc\.php|wp-admin/|wp-content/|wp-includes/).*) HTTP/.*" (400|401|403|404|405|444|499|500|502|503|504) .*
            ^<HOST> - .*"(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH) (/(phpmyadmin|pma|myadmin|phpMyAdmin)/.*) HTTP/.*" (400|401|403|404|405|444|499|500|502|503|504) .*
            ^<HOST> - .*"(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH) (/(\.env|\.git/|\.svn/|\.hg/|\.DS_Store|backup|backups|dump|dumps|db|database|config|conf|\.well-known/).*) HTTP/.*" (400|401|403|404|405|444|499|500|502|503|504) .*
            ^<HOST> - .*"(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH) (/.+\.(bak|old|swp|zip|tar|gz|7z|sql|sqlite|ini|yml|yaml|toml)) HTTP/.*" (400|401|403|404|405|444|499|500|502|503|504) .*
            ^<HOST> - .*"(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH) (/.+\.\./.+) HTTP/.*" (400|401|403|404|405|444|499|500|502|503|504) .*

ignoreregex =
EOF
  chmod 0644 /etc/fail2ban/filter.d/nginx-scan.conf
  log "Wrote custom filter: /etc/fail2ban/filter.d/nginx-scan.conf"
}

write_jail_nginx_scan() {
  mkdir -p /etc/fail2ban/jail.d

  local logpath
  logpath="$(detect_nginx_logpath)"
  local enabled="true"
  if [[ -z "$logpath" ]]; then
    enabled="false"
    log "WARN: nginx log not found under /var/log/nginx; nginx-scan jail will be disabled until logpath is set"
  fi

  cat > /etc/fail2ban/jail.d/nginx-scan-ipset.conf <<EOF
# Custom nginx scanner/probe jail -> ipset blacklist ($DENY_SET)
# This jail uses file logpath (nginx access log).

[nginx-scan]
enabled = ${enabled}
filter = nginx-scan
backend = auto
logpath = ${logpath:-/var/log/nginx/access.log}

# More aggressive defaults for scanners
maxretry = 10
findtime = 10m
bantime  = 12h

action = ipset-deny[set=$DENY_SET,bantime_sec=$(parse_duration_to_seconds "12h"),taglog=$TAG_LOG]
EOF
  chmod 0644 /etc/fail2ban/jail.d/nginx-scan-ipset.conf
  log "Wrote nginx-scan jail: /etc/fail2ban/jail.d/nginx-scan-ipset.conf"
}

write_jail_recidive() {
  mkdir -p /etc/fail2ban/jail.d

  local f2blog=""
  for lf in /var/log/fail2ban.log /var/log/fail2ban/fail2ban.log; do
    [[ -f "$lf" ]] && f2blog="$lf" && break
  done
  [[ -n "$f2blog" ]] || log "WARN: fail2ban log not found; recidive may need manual logpath"

  cat > /etc/fail2ban/jail.d/recidive-ipset.conf <<EOF
# Recidive escalates repeat offenders across jails.

[recidive]
enabled = true
backend = auto
action = ipset-deny[set=$DENY_SET,bantime_sec=$(parse_duration_to_seconds "$BANTIME"),taglog=$TAG_LOG]

# Conservative defaults
maxretry = 5
findtime = 1d
bantime  = 7d
EOF
  if [[ -n "$f2blog" ]]; then
    echo "logpath = $f2blog" >> /etc/fail2ban/jail.d/recidive-ipset.conf
  fi
  chmod 0644 /etc/fail2ban/jail.d/recidive-ipset.conf
  log "Wrote recidive jail: /etc/fail2ban/jail.d/recidive-ipset.conf"
}

jail_exists() {
  # Return 0 if jail exists in fail2ban, else 1
  fail2ban-client status 2>/dev/null | grep -qE "Jail list:" || return 1
  local jl
  jl="$(fail2ban-client status 2>/dev/null | sed -n 's/^`- Jail list:\s*//p')"
  echo "$jl" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -qx "$1"
}


check_no_nft_fail2ban_sets() {
  if ! cmd nft; then
    echo "nft not installed; skip nft set check"
    return 0
  fi
  local found
  found="$(nft list sets 2>/dev/null | grep -E '\b(f2b|fail2ban)\b' || true)"
  if [[ -n "$found" ]]; then
    echo "ERROR: Detected nftables sets that look like fail2ban-managed sets:"
    echo "$found"
    return 1
  fi
  echo "OK: No fail2ban-looking nftables sets detected."
  return 0
}


# ---- Guard: ensure local overrides do not switch banaction back to nftables ----
guard_no_nft_banaction_overrides() {
  # We only inspect local override files that can override our defaults.
  # We DO NOT fail on distro defaults in jail.conf.
  local bad=""
  local files=()

  [[ -f /etc/fail2ban/jail.local ]] && files+=(/etc/fail2ban/jail.local)
  if [[ -d /etc/fail2ban/jail.d ]]; then
    while IFS= read -r f; do files+=("$f"); done < <(find /etc/fail2ban/jail.d -maxdepth 1 -type f \( -name '*.local' -o -name '*.conf' \) 2>/dev/null | sort)
  fi

  local f
  for f in "${files[@]}"; do
    [[ "$f" == "/etc/fail2ban/jail.d/00-ipset-deny-defaults.local" ]] && continue
    if grep -nE '^[[:space:]]*(banaction|banaction_allports)[[:space:]]*=' "$f" 2>/dev/null | grep -E '=.*\bnft' >/dev/null 2>&1; then
      bad+="$f"$'\n'
    fi
  done

  if [[ -n "$bad" ]]; then
    echo "ERROR: Found local fail2ban overrides that set banaction to nftables (will defeat ipset-deny):"
    echo "$bad" | sed '/^$/d' | sed 's/^/  - /'
    echo "Fix: remove/adjust those lines (banaction=...) then rerun install."
    return 1
  fi

  echo "OK: No local overrides forcing nftables banaction."
  return 0
}

# ---- nft cleanup for legacy fail2ban nftables tables/sets/chains ----
nft_backup_ruleset() {
  local dir="/etc/firewall/nft-backups"
  mkdir -p "$dir"
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  local out="${dir}/nft.ruleset.${ts}.backup"
  nft list ruleset > "$out"
  chmod 0600 "$out"
  echo "$out"
}

nft_cleanup_fail2ban_objects() {
  cmd nft || die "nft command not found"

  local backup; backup="$(nft_backup_ruleset)"
  log "Backup saved: $backup"

  local tables
  tables="$(nft -a list tables 2>/dev/null | awk '{print $2" "$3}' | grep -E '(^|[[:space:]])(f2b|fail2ban)[^[:space:]]*$' || true)"

  if [[ -n "$tables" ]]; then
    log "Deleting nftables tables that look like fail2ban:"
    echo "$tables" | while read -r fam name; do
      [[ -n "$fam" && -n "$name" ]] || continue
      log "  nft delete table $fam $name"
      nft delete table "$fam" "$name" || true
    done
  else
    log "No nftables tables named like f2b/fail2ban found."
  fi

  local sets
  sets="$(nft list sets 2>/dev/null | grep -E '\b(f2b|fail2ban)\b' || true)"
  if [[ -n "$sets" ]]; then
    log "WARNING: nft list sets still shows f2b/fail2ban strings after cleanup."
    log "Inspect manually (might be other tables not named f2b/fail2ban):"
    echo "$sets"
  fi

  log "Cleanup done."
  log "Rollback command (RESTORES FULL ruleset from backup; use with care):"
  log "  $0 rollback-nft $backup"
}

nft_rollback_from_backup() {
  local file="${1:-}"
  [[ -n "$file" ]] || die "usage: $0 rollback-nft <backup_file>"
  [[ -f "$file" ]] || die "backup file not found: $file"
  cmd nft || die "nft not installed"
  log "Restoring nft ruleset from backup: $file"
  nft -f "$file"
  log "Rollback completed."
}

# ---------------- Evidence / Guard ----------------

prove_no_iptables_rules() {
  echo "== Evidence: fail2ban action lines (from fail2ban-client -d) =="
  if cmd fail2ban-client; then
    fail2ban-client -d 2>/dev/null | grep -E '^[[:space:]]*action[[:space:]]*=' || true
  else
    echo "fail2ban-client not found"
  fi
  echo

  echo "== Evidence: iptables has no fail2ban chains (f2b-*) =="
  if command -v iptables >/dev/null 2>&1; then
    if iptables -S 2>/dev/null | grep -qiE 'f2b-|fail2ban'; then
      echo "WARN: found fail2ban-related chains in iptables:"
      iptables -S 2>/dev/null | grep -iE 'f2b-|fail2ban' || true
    else
      echo "OK: no f2b-* / fail2ban chains in iptables"
    fi
  else
    echo "iptables not found; skip"
  fi
  echo

  echo "== Evidence: fail2ban log does not show iptables usage (best-effort) =="
  for lf in /var/log/fail2ban.log /var/log/fail2ban/fail2ban.log; do
    if [[ -f "$lf" ]]; then
      if grep -qi iptables "$lf"; then
        echo "WARN: '$lf' contains 'iptables' entries (check!)"
        grep -i iptables "$lf" | tail -n 20 || true
      else
        echo "OK: no 'iptables' strings in $lf"
      fi
    fi
  done
}

cmd_status() {
  echo "== fail2ban status =="
  if cmd fail2ban-client; then
    fail2ban-client status || true
    echo
    for j in sshd nginx-http-auth nginx-badbots recidive; do
      if jail_exists "$j"; then fail2ban-client status "$j" 2>/dev/null || true; echo; fi
    done
  else
    echo "fail2ban-client not found"
  fi
  echo
  echo "== ipset $DENY_SET =="
  ipset list "$DENY_SET" 2>/dev/null | sed -n '1,120p' || true
  echo
  echo "== tag log tail =="
  tail -n 30 "$TAG_LOG" 2>/dev/null || true
}

cmd_selfcheck() {
  echo \"== Check: Fail2ban must not use nftables sets ==\"
  check_no_nft_fail2ban_sets || true
  echo

  need_root
  echo "== Guard audit (config) =="
  /usr/local/sbin/fail2ban-action-audit.sh && echo "OK: no unsafe actions detected"
  echo
  prove_no_iptables_rules
  echo
  echo "== ipset deny set health =="
  ipset list -n 2>/dev/null | grep -qx "$DENY_SET" && echo "OK: ipset set exists: $DENY_SET" || echo "WARN: ipset set missing: $DENY_SET"
}

cmd_disable_iptables() {
  need_root
  local changed="false"
  for f in /etc/fail2ban/action.d/iptables*.conf /etc/fail2ban/action.d/nftables*.conf /etc/fail2ban/action.d/firewallcmd*.conf /etc/fail2ban/action.d/ufw*.conf; do
    [[ -f "$f" ]] || continue
    chmod 000 "$f" || true
    changed="true"
  done
  if [[ "$changed" == "true" ]]; then
    log "Hard-disabled built-in iptables/nftables/firewalld/ufw actions (chmod 000) (best-effort)"
  else
    log "No built-in iptables/nftables/firewalld/ufw action files found under /etc/fail2ban/action.d"
  fi
  restart_fail2ban || true
}


cmd_upgrade_timeout() {
  need_root
  local set="${UPGRADE_SET:-$DENY_SET}"
  local t="${UPGRADE_TIMEOUT:-$BANTIME}"
  local timeout_sec; timeout_sec="$(parse_duration_to_seconds "$t")"
  upgrade_ipset_timeout "$set" "$timeout_sec"
}

cmd_rollback_timeout() {
  need_root
  local f="${1:-}"
  [[ -n "$f" ]] || die "usage: $0 rollback-timeout <backup_file>"
  rollback_ipset_from_backup "$f"
}

cmd_bootfix() {
  need_root

  local dropdir="/etc/systemd/system/fail2ban.service.d"
  mkdir -p "$dropdir"

  # If user has a firewall service unit, chain ordering after it as well.
  local after_fw=""
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "fw-22-80-443-ipset.service"; then
    after_fw=" fw-22-80-443-ipset.service"
  fi

  # Ensure kernel modules and ipset set exist BEFORE fail2ban-server starts.
  # We keep it idempotent and fast.
  cat > "${dropdir}/20-ipset-pre.conf" <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
# Ensure ipset kernel modules are present (best-effort)
ExecStartPre=/sbin/modprobe ip_set 2>/dev/null || true
ExecStartPre=/sbin/modprobe ip_set_hash_net 2>/dev/null || true
ExecStartPre=/sbin/modprobe ip_set_hash_ip 2>/dev/null || true

# Ensure target ipset exists before fail2ban starts.
ExecStartPre=/bin/bash -c 'IPSET="$(command -v ipset || true)"; [ -n "$IPSET" ] || IPSET="/usr/sbin/ipset"; "$IPSET" list -n 2>/dev/null | grep -qx "deny_src" || "$IPSET" create "deny_src" hash:net family inet hashsize 1024 maxelem 65536 -exist'

# Optional: ensure taglog path exists
ExecStartPre=/bin/bash -c 'mkdir -p "/var/log"; touch "/var/log/fail2ban-ipset-tags.log"; chmod 0644 "/var/log/fail2ban-ipset-tags.log" || true'
EOF

  systemctl daemon-reload
  log "Installed systemd drop-in: ${dropdir}/20-ipset-pre.conf"
  log "Now reboot, or run: systemctl restart fail2ban"
}

cmd_cleanup_nft() {
  need_root
  nft_cleanup_fail2ban_objects
}

cmd_rollback_nft() {
  need_root
  nft_rollback_from_backup "${1:-}"
}

cmd_uninstall() {
  need_root
  rm -f /etc/fail2ban/jail.d/sshd-ipset.conf
  rm -f /etc/fail2ban/jail.d/nginx-ipset.conf
  rm -f /etc/fail2ban/jail.d/recidive-ipset.conf
  rm -f /etc/fail2ban/jail.d/00-ipset-default.conf
  rm -f /etc/fail2ban/action.d/ipset-deny.conf
  rm -f /usr/local/sbin/fail2ban-action-audit.sh
  rm -f /etc/systemd/system/fail2ban.service.d/10-no-iptables.conf

  if cmd systemctl; then systemctl daemon-reload || true; fi
  restart_fail2ban || true
  log "Uninstall complete (removed only files created by this script)"
}

cmd_install() {
  need_root
  install_pkgs
  ensure_ipset
  write_action
  write_defaults
  write_guard
  write_jail_sshd
  restart_fail2ban

  log "DONE."
  log "Next:"
  log "  sudo $0 selfcheck"
  log "  sudo $0 enable-nginx     # optional"
  log "  sudo $0 enable-recidive  # optional"

  # Guard: prevent regressions to nftables banaction via local overrides.
  guard_no_nft_banaction_overrides

}

cmd_enable_nginx() {
  need_root
  [[ -f /etc/fail2ban/action.d/ipset-deny.conf ]] || die "ipset action missing; run: $0 install"
  write_jail_nginx
  restart_fail2ban
  log "Enabled nginx jails (best-effort). Run: sudo $0 status"

  # Guard: prevent regressions to nftables banaction via local overrides.
  guard_no_nft_banaction_overrides

}

cmd_enable_nginx_scan() {
  need_root
  [[ -f /etc/fail2ban/action.d/ipset-deny.conf ]] || die "ipset action missing; run: $0 install"
  install_filter_nginx_scan
  write_jail_nginx_scan
  restart_fail2ban
  log "Enabled nginx-scan jail (best-effort). Run: sudo $0 status"

  # Guard: prevent regressions to nftables banaction via local overrides.
  guard_no_nft_banaction_overrides

}

cmd_enable_recidive() {
  need_root
  [[ -f /etc/fail2ban/action.d/ipset-deny.conf ]] || die "ipset action missing; run: $0 install"
  write_jail_recidive
  restart_fail2ban
  log "Enabled recidive jail. Run: sudo $0 status"

  # Guard: prevent regressions to nftables banaction via local overrides.
  guard_no_nft_banaction_overrides

}

usage() {
  cat <<EOF
Usage:
  sudo $0 install
  sudo $0 enable-nginx
  sudo $0 enable-nginx-scan
  sudo $0 enable-recidive
  sudo $0 selfcheck
  sudo $0 status
  sudo $0 disable-iptables
  sudo $0 upgrade-timeout
  sudo $0 rollback-timeout /etc/firewall/ipset-backups/deny_src.<ts>.save
  sudo $0 uninstall

Env overrides:
  DENY_SET=deny_src
  SSH_PORT=22
  MAXRETRY=5
  FINDTIME=10m
  BANTIME=1h
  BACKEND=systemd|auto|polling
  USE_IPSET_TIMEOUT=true|false
  TAG_LOG=/var/log/fail2ban-ipset-tags.log
  GUARD_BLOCK=true|false
  # upgrade-timeout only
  UPGRADE_SET=deny_src
  UPGRADE_TIMEOUT=1h   # default = BANTIME

Notes:
  - enable-nginx uses packaged filters (nginx-http-auth, nginx-badbots).
  - enable-nginx-scan installs a custom filter (nginx-scan) that watches access.log for common probes.
  - With BACKEND=systemd, logpath is usually not needed. With file backends, set logpath.
EOF
}

main() {
  local c="${1:-}"
  case "$c" in
    install) shift; cmd_install "$@" ;;
    enable-nginx) shift; cmd_enable_nginx "$@" ;;
    enable-nginx-scan) shift; cmd_enable_nginx_scan "$@" ;;
    enable-recidive) shift; cmd_enable_recidive "$@" ;;
    selfcheck) shift; cmd_selfcheck "$@" ;;
    status) shift; cmd_status "$@" ;;
    disable-iptables) shift; cmd_disable_iptables "$@" ;;
    upgrade-timeout) shift; cmd_upgrade_timeout "$@" ;;
    rollback-timeout) shift; cmd_rollback_timeout "$@" ;;
    bootfix) shift; cmd_bootfix "$@" ;;
    cleanup-nft) shift; cmd_cleanup_nft "$@" ;;
    rollback-nft) shift; cmd_rollback_nft "$@" ;;
    uninstall) shift; cmd_uninstall "$@" ;;
    ""|help|-h|--help) usage ;;
    *) die "unknown command: $c (use: $0 help)" ;;
  esac
}

main "$@"
