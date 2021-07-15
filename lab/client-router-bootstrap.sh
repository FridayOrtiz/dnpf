#!/usr/bin/env bash

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -y
apt-get install -y build-essential clang llvm libclang-dev linux-tools-oem \
  linux-tools-5.4.0-58-generic iptables-persistent

#su vagrant << EOF
#  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#  # Installing cargo-with allows for `cargo with "strace -fe bpf" -- test` while testing
#  source /home/vagrant/.cargo/env
#  cargo install cargo-with
#EOF

#ip route add 192.168.75.0/24 via 192.168.50.1 dev eth1
echo 1 > /proc/sys/net/ipv4/ip_forward

ip link set eth1 down
ip link set eth2 down
ip link set eth1 up
ip link set eth2 up

iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE
iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

