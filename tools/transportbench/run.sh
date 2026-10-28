#!/bin/sh
# Runs transportbench under each network scenario. Must run as root inside a
# disposable Linux container (see `make bench-transport`): it reshapes the
# container's loopback interface.
set -eu

BENCH=${BENCH:-/bench/transportbench}

apk add --quiet --no-progress iproute2 ethtool >/dev/null

# Make loopback behave like a real link: Ethernet MTU and no segmentation
# offload, so netem drops individual packets instead of 64 KiB super-packets.
# Offloads left on would penalize TCP far more than QUIC (GSO is disabled for
# quic-go below), so a failure here aborts the run.
ip link set lo mtu 1500
ethtool -K lo tso off gso off gro off
for feature in tcp-segmentation-offload generic-segmentation-offload generic-receive-offload; do
	if ! ethtool -k lo | grep -q "^$feature: off"; then
		echo "run.sh: $feature is still on for lo; results would be skewed" >&2
		exit 1
	fi
done
export QUIC_GO_DISABLE_GSO=true

# quic-go wants larger UDP buffers than most distro defaults.
sysctl -q -w net.core.rmem_max=7500000 net.core.wmem_max=7500000

# Each scenario: label, one-way delay, per-packet loss, link rate. netem on
# lo applies delay and loss once per direction, so RTT is twice the delay
# and data and ACKs are both dropped at the given rate. The queue limit is
# large enough that tail drops do not add loss beyond the configured rate.
scenarios="
30ms-rtt,15ms,0%,50mbit
50ms-rtt-0.5%-loss,25ms,0.5%,50mbit
100ms-rtt-1%-loss,50ms,1%,50mbit
"

"$BENCH" -header
for s in $scenarios; do
	IFS=, read -r label delay loss rate <<EOF
$s
EOF
	tc qdisc replace dev lo root netem delay "$delay" loss "$loss" rate "$rate" limit 10000
	"$BENCH" -label "$label"
	# Sent/dropped counters let the reader check drops match the configured loss.
	echo "  netem $label: $(tc -s qdisc show dev lo | grep -o 'Sent [0-9]* bytes [0-9]* pkt (dropped [0-9]*')" >&2
	tc qdisc del dev lo root
done
