#!/bin/sh
# Verifies install.sh resolves the correct release archive URL for the host.
set -eu
root="$(CDPATH='' cd "$(dirname "$0")/../.." && pwd)"

out="$(DRY_RUN=1 EYEBROW_VERSION=0.2.0 sh "$root/install.sh")"

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unexpected arch $(uname -m)" >&2; exit 1 ;;
esac
case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) echo "unexpected os $(uname -s)" >&2; exit 1 ;;
esac
want="eyebrow_0.2.0_${os}_${arch}.tar.gz"

echo "$out" | grep -q "$want" || {
  echo "FAIL: resolved URL did not contain $want" >&2
  echo "got: $out" >&2
  exit 1
}
echo "PASS: $out"
