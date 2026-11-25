#!/bin/sh
# Root-only integration. Both endpoints live in namespaces without a default route.
set -eu
core=$(realpath "$1")
cd "$(dirname "$0")"
ip_tool=${IP:-ip}
left="mbx-gateway-$$"
right="mbx-destination-$$"
cleanup() {
    "$ip_tool" netns delete "$left" 2>/dev/null || :
    "$ip_tool" netns delete "$right" 2>/dev/null || :
}
trap cleanup EXIT
"$ip_tool" netns add "$left"
"$ip_tool" netns add "$right"
"$ip_tool" -n "$left" link add eth0 type veth peer name eth0 netns "$right"
"$ip_tool" -n "$left" addr add 93.184.216.33/30 dev eth0
"$ip_tool" -n "$right" addr add 93.184.216.34/30 dev eth0
for ns in "$left" "$right"; do
    "$ip_tool" -n "$ns" link set lo up
    "$ip_tool" -n "$ns" link set eth0 up
done
"$ip_tool" netns exec "$left" env MAGICBOX_TEST_DEST_NS="$right" python3 tunnels.py "$core" VerifiedHttps.test_client_gateway_dot_and_duplex VerifiedHttps.test_bootstrap_redirect_chunked_agent_and_private_address_denial VerifiedHttps.test_named_https_node_tunnels_using_pinned_peers_and_original_identity
