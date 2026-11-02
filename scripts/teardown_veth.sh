#!/usr/bin/env bash
# ==============================================================================
# teardown_veth.sh - Clean up test network namespace and virtual interfaces
# ==============================================================================
set -euo pipefail

NETNS="abyss-ns"
ABYSS_IFACE="veth-abyss"

if ip netns list | grep -q "${NETNS}"; then
    echo "[-] Deleting namespace ${NETNS}..."
    sudo ip netns del "${NETNS}"
fi

if ip link show "${ABYSS_IFACE}" &>/dev/null; then
    echo "[-] Removing interface ${ABYSS_IFACE}..."
    sudo ip link del "${ABYSS_IFACE}"
fi

echo "[✓] Test environment cleaned up."
