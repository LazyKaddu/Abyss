#!/usr/bin/env bash
# ==============================================================================
# setup_veth.sh - Setup isolated network namespace and veth pair for Abyss
# ==============================================================================
set -euo pipefail

NETNS="abyss-ns"
ABYSS_IFACE="veth-abyss"
PEER_IFACE="veth-peer"
ABYSS_IP="10.200.1.1/24"
PEER_IP="10.200.1.2/24"

echo "[+] Setting up isolated network namespace for Abyss testing..."

# Clean up previous namespace if exists
if ip netns list | grep -q "${NETNS}"; then
    echo "[-] Cleaning up old namespace ${NETNS}..."
    sudo ip netns del "${NETNS}"
fi

# Clean up previous veth-abyss interface if exists
if ip link show "${ABYSS_IFACE}" &>/dev/null; then
    echo "[-] Removing existing ${ABYSS_IFACE}..."
    sudo ip link del "${ABYSS_IFACE}"
fi

# 1. Create isolated network namespace for the sender peer
echo "[+] Creating network namespace: ${NETNS}"
sudo ip netns add "${NETNS}"

# 2. Create the veth pair
echo "[+] Creating veth pair: ${ABYSS_IFACE} <---> ${PEER_IFACE}"
sudo ip link add "${ABYSS_IFACE}" type veth peer name "${PEER_IFACE}"

# 3. Move veth-peer into the isolated namespace
echo "[+] Moving ${PEER_IFACE} into namespace ${NETNS}"
sudo ip link set "${PEER_IFACE}" netns "${NETNS}"

# 4. Configure host side (Abyss XDP target)
echo "[+] Configuring host interface ${ABYSS_IFACE} (${ABYSS_IP})"
sudo ip addr add "${ABYSS_IP}" dev "${ABYSS_IFACE}"
sudo ip link set "${ABYSS_IFACE}" up

# 5. Configure namespace side (Traffic generator peer)
echo "[+] Configuring namespace interface ${PEER_IFACE} (${PEER_IP})"
sudo ip -n "${NETNS}" addr add "${PEER_IP}" dev "${PEER_IFACE}"
sudo ip -n "${NETNS}" link set "${PEER_IFACE}" up
sudo ip -n "${NETNS}" link set lo up

echo ""
echo "[✓] Isolated test environment ready!"
echo "    - Abyss Ingress Interface (Host):      ${ABYSS_IFACE} (${ABYSS_IP})"
echo "    - Generator Peer Interface (${NETNS}): ${PEER_IFACE} (${PEER_IP})"
echo ""
echo "To generate test traffic across the XDP program:"
echo "    sudo ip netns exec ${NETNS} ping -c 5 10.200.1.1"
echo ""
echo "To tear down:"
echo "    ./scripts/teardown_veth.sh"
