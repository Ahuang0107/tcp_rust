#! /bin/bash
cargo b -r
ext=$?
echo "$ext"
if [[ $ext -ne 0 ]]; then
  exit $ext
fi
target/release/tcp_rust &
pid=$!
ip addr add 192.168.0.1/24 dev tun0
ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid