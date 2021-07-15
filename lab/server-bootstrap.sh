#!/usr/bin/env bash

#export DEBIAN_FRONTEND=noninteractive

#echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections

apt-get update
apt-get upgrade -y
apt-get install -y build-essential clang llvm libclang-dev linux-tools-oem \
  linux-tools-5.4.0-58-generic

#su vagrant << EOF
#  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#  # Installing cargo-with allows for `cargo with "strace -fe bpf" -- test` while testing
#  source /home/vagrant/.cargo/env
#  cargo install cargo-with
#EOF

ip route add 192.168.50.0/24 via 192.168.75.2 metric 10

ip link set eth1 down
ip link set eth1 up

echo '192.168.50.5	client' >> /etc/hosts

