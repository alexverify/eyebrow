#!/bin/sh
# eyebrow installer: download a checksum-verified release binary onto PATH.
# Usage: curl -fsSL https://raw.githubusercontent.com/alexverify/eyebrow/main/install.sh | sh
# Env: EYEBROW_VERSION (e.g. 0.2.0), INSTALL_DIR, DRY_RUN=1
set -eu

REPO="alexverify/eyebrow"

detect_os() {
  case "$(uname -s)" in
    Darwin) echo darwin ;;
    Linux)  echo linux ;;
    *) echo "unsupported OS: $(uname -s) (try 'go install' or a manual download)" >&2; exit 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
}

resolve_version() {
  if [ -n "${EYEBROW_VERSION:-}" ]; then
    echo "${EYEBROW_VERSION#v}"
    return
  fi
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 \
    | sed -E 's/.*"tag_name" *: *"v?([^"]+)".*/\1/'
}

main() {
  os="$(detect_os)"
  arch="$(detect_arch)"
  version="$(resolve_version)"
  [ -n "$version" ] || { echo "could not resolve a release version" >&2; exit 1; }

  archive="eyebrow_${version}_${os}_${arch}.tar.gz"
  base="https://github.com/${REPO}/releases/download/v${version}"
  url="${base}/${archive}"

  if [ "${DRY_RUN:-}" = "1" ]; then
    echo "$url"
    return 0
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "downloading $url" >&2
  curl -fsSL "$url" -o "$tmp/$archive"
  curl -fsSL "${base}/checksums.txt" -o "$tmp/checksums.txt"

  echo "verifying checksum" >&2
  checksum_line="$(grep " ${archive}\$" "$tmp/checksums.txt" || true)"
  [ -n "$checksum_line" ] || { echo "no checksum entry for $archive in checksums.txt" >&2; exit 1; }
  ( cd "$tmp" && printf '%s\n' "$checksum_line" | sha256_check )

  tar -xzf "$tmp/$archive" -C "$tmp"

  dir="${INSTALL_DIR:-/usr/local/bin}"
  if [ ! -w "$dir" ] && [ "$dir" = "/usr/local/bin" ]; then
    dir="$HOME/.local/bin"
  fi
  mkdir -p "$dir"
  install -m 0755 "$tmp/eyebrow" "$dir/eyebrow"
  echo "installed eyebrow $version -> $dir/eyebrow" >&2
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "note: $dir is not on your PATH; add it (e.g. export PATH=\"$dir:\$PATH\")" >&2 ;;
  esac
}

# Verify a 'sha256  filename' line on stdin using whichever tool is present.
sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c -
  else
    echo "no sha256 tool (sha256sum/shasum) found" >&2
    exit 1
  fi
}

main "$@"
