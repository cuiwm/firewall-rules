#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 cuiwm
#
# Script:
#   fw-22-80-443-ipset-restore.sh
#
# Description:
#   Restore iptables and ipset rules created by
#   fw-22-80-443-ipset.sh after system reboot.
#
# Usage:
#   ./fw-22-80-443-ipset-restore.sh
#
# Safety:
#   - Must be run as root
#   - Intended to be executed during system boot

set -euo pipefail

FW_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FW_MAIN_SCRIPT="${FW_SCRIPT_DIR}/fw-22-80-443-ipset.sh"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must be run as root" >&2
  exit 1
fi

if [[ ! -x "$FW_MAIN_SCRIPT" ]]; then
  echo "ERROR: firewall script not found or not executable: $FW_MAIN_SCRIPT" >&2
  exit 1
fi

echo "[INFO] Restoring firewall rules via fw-22-80-443-ipset.sh"

"$FW_MAIN_SCRIPT" install

echo "[INFO] Firewall rules restored successfully"

