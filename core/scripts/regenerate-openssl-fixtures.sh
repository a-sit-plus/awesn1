#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "$script_dir/../.." && pwd)"
out_dir="$project_root/core/src/jvmTest/resources/fixtures/openssl"

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl not found in PATH" >&2
  exit 1
fi

mkdir -p "$out_dir"
rm -f "$out_dir"/*.pem

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# Core private/public key fixtures
openssl genrsa -out "$work_dir/rsa-traditional.pem" 2048 >/dev/null 2>&1
openssl rsa -in "$work_dir/rsa-traditional.pem" -traditional -out "$out_dir/rsa-private-traditional.pem" >/dev/null 2>&1
openssl pkcs8 -topk8 -nocrypt -in "$work_dir/rsa-traditional.pem" -out "$out_dir/rsa-private-pkcs8.pem" >/dev/null 2>&1
openssl rsa -in "$work_dir/rsa-traditional.pem" -traditional -aes256 -passout pass:password -out "$out_dir/rsa-private-traditional-encrypted.pem" >/dev/null 2>&1
openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 2048 -in "$work_dir/rsa-traditional.pem" -passout pass:password -out "$out_dir/rsa-private-pkcs8-encrypted.pem" >/dev/null 2>&1
openssl pkey -in "$work_dir/rsa-traditional.pem" -pubout -out "$out_dir/rsa-public.pem" >/dev/null 2>&1

# Certificate fixtures
openssl req -new -x509 -key "$work_dir/rsa-traditional.pem" -subj "/CN=awesn1 pem fixture" -days 365 -sha256 -out "$out_dir/certificate.pem" >/dev/null 2>&1

# EC traditional key fixture
openssl ecparam -name prime256v1 -genkey -noout -out "$work_dir/ec-private.pem" >/dev/null 2>&1
openssl ec -in "$work_dir/ec-private.pem" -out "$out_dir/ec-private-traditional.pem" >/dev/null 2>&1

# Multi-block fixture variants
cat "$out_dir/certificate.pem" "$out_dir/certificate.pem" > "$out_dir/certificate-chain.pem"
cat "$out_dir/certificate.pem" "$out_dir/rsa-public.pem" "$out_dir/rsa-private-pkcs8-encrypted.pem" > "$out_dir/mixed-bundle.pem"

echo "Regenerated OpenSSL PEM fixtures using: $(openssl version)"
echo "Output directory: $out_dir"
ls -1 "$out_dir"
