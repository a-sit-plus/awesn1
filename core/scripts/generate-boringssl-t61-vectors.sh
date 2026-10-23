#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 BORINGSSL_CHECKOUT [OUTPUT_JSON]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checkout="$(cd "$1" && pwd)"
output="${2:-$script_dir/../src/commonTest/resources/fixtures/boringssl/t61.json}"

if [[ -f "$checkout/src/include/openssl/asn1.h" ]]; then
  source_root="$checkout/src"
elif [[ -f "$checkout/include/openssl/asn1.h" ]]; then
  source_root="$checkout"
else
  echo "error: not a BoringSSL checkout: $checkout" >&2
  exit 1
fi

build_dir="${BORINGSSL_BUILD_DIR:-$checkout/.awesn1-build}"
libcrypto="$build_dir/crypto/libcrypto.a"
if [[ -f "$build_dir/libcrypto.a" ]]; then
  libcrypto="$build_dir/libcrypto.a"
elif [[ ! -f "$libcrypto" ]]; then
  cmake -S "$source_root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
  cmake --build "$build_dir" --target crypto --parallel
fi
if [[ -f "$build_dir/libcrypto.a" ]]; then
  libcrypto="$build_dir/libcrypto.a"
fi
if [[ ! -f "$libcrypto" ]]; then
  echo "error: BoringSSL build did not produce $libcrypto" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"
binary="$(mktemp -t awesn1-t61-vectors.XXXXXX)"
trap 'rm -f "$binary"' EXIT
"${CXX:-c++}" -std=c++17 -I"$source_root/include" \
  "$script_dir/boringssl-t61-vectors.cc" "$libcrypto" -pthread -o "$binary"
"$binary" > "$output"
echo "Wrote $output"
