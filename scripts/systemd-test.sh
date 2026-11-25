#!/usr/bin/env bash
# Runs the packaged systemd unit (packaging/gre-controller.service) under the real
# systemd, inside a throwaway network namespace, and checks that it creates the
# declared tunnels, logs to the journal with priorities, and keeps the tunnels when
# stopped.
#
# This installs files into /usr/bin and /etc and starts a system service, so run it
# only on a disposable machine such as a CI runner. Needs root through sudo.
set -euo pipefail

fail() {
    echo "$1" >&2
    exit 1
}

if [[ -e /etc/systemd/system/gre-controller.service || -e /usr/bin/gre-controller ]]; then
    echo "gre-controller is already installed here; refusing to overwrite it" >&2
    exit 1
fi

ns="gre-controller-systemd-$$"
unit=gre-controller.service
dropin=/etc/systemd/system/$unit.d

cleanup() {
    echo "Journal of $unit:"
    sudo journalctl -u "$unit" --no-pager -n 50 || true
    sudo systemctl stop "$unit" || true
    sudo rm -rf /usr/bin/gre-controller /etc/systemd/system/$unit "$dropin" /etc/gre-controller
    sudo systemctl daemon-reload
    sudo ip netns delete "$ns" || true
}

cargo build --locked
trap cleanup EXIT

sudo install -m 0755 target/debug/gre-controller /usr/bin/gre-controller
sudo install -m 0644 packaging/gre-controller.service /etc/systemd/system/$unit
sudo install -d -m 0755 /etc/gre-controller
sudo tee /etc/gre-controller/config.toml >/dev/null <<'EOF'
[tunnels.sd-gre]
family = "ipv4"
local = "192.0.2.90"
remote = "198.51.100.90"
addresses = ["10.9.0.1/30"]

[tunnels.sd-gre6]
family = "ipv6"
local = "2001:db8::90"
remote = "2001:db8::91"
addresses = ["10.9.1.1/30", "fd00:9::1/64"]
EOF
sudo chmod 0644 /etc/gre-controller/config.toml

# The service joins this namespace instead of the runner's own.
sudo ip netns add "$ns"
sudo ip -n "$ns" link set lo up
sudo ip -n "$ns" link add uplink type veth peer name uplink-peer
sudo ip -n "$ns" address add 192.0.2.90/24 dev uplink
sudo ip -n "$ns" address add 2001:db8::90/64 dev uplink nodad
sudo install -d -m 0755 "$dropin"
printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$ns" | sudo tee "$dropin/netns.conf" >/dev/null

sudo systemd-analyze verify /etc/systemd/system/$unit
echo "GRE modules before start:"
lsmod | grep -E '^(ip_gre|ip6_gre|gre) ' || echo "  (none loaded)"

sudo systemctl daemon-reload
sudo systemctl start "$unit"

# Wait for both tunnels.
for _ in $(seq 60); do
    if sudo ip -n "$ns" link show sd-gre >/dev/null 2>&1 &&
        sudo ip -n "$ns" link show sd-gre6 >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
echo "GRE modules after start:"
lsmod | grep -E '^(ip_gre|ip6_gre|gre) ' || echo "  (none loaded)"
sudo ip -n "$ns" -d link show sd-gre
sudo ip -n "$ns" -d link show sd-gre6
sudo ip -n "$ns" address show dev sd-gre6

for link in sd-gre sd-gre6; do
    details=$(sudo ip -n "$ns" -d link show "$link")
    grep -q 'alias gre-controller' <<<"$details" || fail "$link is not marked"
done
# The service runs in the namespace, not in the runner's network.
if ip link show sd-gre >/dev/null 2>&1; then
    fail "sd-gre was created outside the test namespace"
fi

# Each check reads the whole journal first, so that `grep -q` cannot cut a pipe short.
journal() {
    sudo journalctl -u "$unit" -o json --no-pager | jq -r "$1"
}
echo "Journal:"
journal '"\(.PRIORITY) \(.MESSAGE)"'
# Priorities come from the `<N>` prefix, which journald removes from the message.
created=$(journal 'select(.PRIORITY == "6" and (.MESSAGE | test("created"))) | .MESSAGE')
grep -q sd-gre6 <<<"$created" || fail "no INFO entry for creating sd-gre6"
messages=$(journal '.MESSAGE')
if grep -q '^<' <<<"$messages"; then fail "a priority prefix was not consumed by journald"; fi
warnings=$(journal 'select(.PRIORITY <= "4") | .MESSAGE')
[[ -z $warnings ]] || fail "unexpected warnings or errors: $warnings"

sudo systemctl stop "$unit"
grep -q stopped <<<"$(journal '.MESSAGE')" || fail "no \"stopped\" entry"
[[ $(systemctl show -p Result --value "$unit") == success ]]
# Stopping does not remove the tunnels.
sudo ip -n "$ns" link show sd-gre >/dev/null
sudo ip -n "$ns" link show sd-gre6 >/dev/null

echo "Hardening summary (informational):"
sudo systemd-analyze security "$unit" --no-pager | tail -n 1 || true
echo "systemd test passed"
