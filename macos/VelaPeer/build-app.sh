#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PACKAGE_DIR="${SCRIPT_DIR}"
RUST_LIB_DIR="${PACKAGE_DIR}/Rust"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
SIGNING_DIR="${BUILD_DIR}/signing"
SIGNING_KEYCHAIN="${SIGNING_DIR}/vela-peer-build.keychain-db"
SIGNING_SOURCE="${PACKAGE_DIR}/Shared/PeerSigningIdentity.swift"
APP_VERSION="${VELA_APP_VERSION:-0.0.0}"
BUILD_VERSION="${VELA_BUILD_VERSION:-${GITHUB_RUN_NUMBER:-1}}"
MACOSX_DEPLOYMENT_TARGET="${VELA_MACOS_DEPLOYMENT_TARGET:-13.0}"
export MACOSX_DEPLOYMENT_TARGET

if [[ ! "${APP_VERSION}" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
  echo "VELA_APP_VERSION must contain dot-separated numbers" >&2
  exit 2
fi
if [[ "${VELA_REQUIRE_PERSISTENT_SIGNING:-0}" == "1" \
  && -z "${VELA_MACOS_SIGNING_P12_BASE64:-}" ]]; then
  echo "Release builds require the persistent Vela code-signing identity secrets" >&2
  exit 2
fi

rustup target add aarch64-apple-darwin x86_64-apple-darwin
cmp "${REPO_ROOT}/vela-peer-service/include/vela_peer_service.h" \
  "${PACKAGE_DIR}/FFI/include/vela_peer_service.h"

cargo build --locked --release --target aarch64-apple-darwin -p vela-peer-service
cargo build --locked --release --target x86_64-apple-darwin -p vela-peer-service

mkdir -p "${RUST_LIB_DIR}" "${BUILD_DIR}" "${DIST_DIR}"
lipo -create \
  "${REPO_ROOT}/target/aarch64-apple-darwin/release/libvela_peer_service.a" \
  "${REPO_ROOT}/target/x86_64-apple-darwin/release/libvela_peer_service.a" \
  -output "${RUST_LIB_DIR}/libvela_peer_service.a"

if [[ -e "${SIGNING_SOURCE}" ]]; then
  echo "Refusing to overwrite ${SIGNING_SOURCE}" >&2
  exit 2
fi

mkdir -p "${SIGNING_DIR}"
TRUSTED_CERT_ADDED=0
cleanup_signing() {
  rm -f "${SIGNING_SOURCE}"
  if [[ "${TRUSTED_CERT_ADDED}" == "1" && -f "${SIGNING_DIR}/certificate.pem" ]]; then
    security remove-trusted-cert "${SIGNING_DIR}/certificate.pem" >/dev/null 2>&1 || true
  fi
  security delete-keychain "${SIGNING_KEYCHAIN}" >/dev/null 2>&1 || true
  rm -rf "${SIGNING_DIR}"
}
trap cleanup_signing EXIT

KEYCHAIN_PASSWORD="$(openssl rand -hex 32)"
P12_PASSWORD="${VELA_MACOS_SIGNING_P12_PASSWORD:-}"
if [[ -n "${VELA_MACOS_SIGNING_P12_BASE64:-}" ]]; then
  printf '%s' "${VELA_MACOS_SIGNING_P12_BASE64}" \
    | base64 -D > "${SIGNING_DIR}/identity.p12"
  if [[ -z "${P12_PASSWORD}" ]]; then
    echo "VELA_MACOS_SIGNING_P12_PASSWORD is required with a persistent signing identity" >&2
    exit 2
  fi
else
  P12_PASSWORD="$(openssl rand -hex 32)"
  cat > "${SIGNING_DIR}/openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = code_signing
prompt = no

[subject]
CN = Vela Peer Build Identity

[code_signing]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -config "${SIGNING_DIR}/openssl.cnf" \
    -keyout "${SIGNING_DIR}/private-key.pem" \
    -out "${SIGNING_DIR}/certificate.pem"
  openssl pkcs12 -export \
    -inkey "${SIGNING_DIR}/private-key.pem" \
    -in "${SIGNING_DIR}/certificate.pem" \
    -name "Vela Peer Build Identity" \
    -passout "pass:${P12_PASSWORD}" \
    -out "${SIGNING_DIR}/identity.p12"
fi
openssl pkcs12 -in "${SIGNING_DIR}/identity.p12" -clcerts -nokeys \
  -passin "pass:${P12_PASSWORD}" -out "${SIGNING_DIR}/certificate.pem"
security create-keychain -p "${KEYCHAIN_PASSWORD}" "${SIGNING_KEYCHAIN}"
security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${SIGNING_KEYCHAIN}"
security import "${SIGNING_DIR}/identity.p12" \
  -k "${SIGNING_KEYCHAIN}" -P "${P12_PASSWORD}" \
  -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list \
  -S apple-tool:,apple: -s -k "${KEYCHAIN_PASSWORD}" "${SIGNING_KEYCHAIN}"
if ! security verify-cert -c "${SIGNING_DIR}/certificate.pem" -p codeSign \
  -k "${SIGNING_KEYCHAIN}" >/dev/null 2>&1; then
  security add-trusted-cert -r trustRoot -p codeSign \
    -k "${SIGNING_KEYCHAIN}" "${SIGNING_DIR}/certificate.pem"
  TRUSTED_CERT_ADDED=1
fi
SIGNING_CERTIFICATE_SHA1="$(openssl x509 -in "${SIGNING_DIR}/certificate.pem" \
  -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
if ! security find-identity -v -p codesigning "${SIGNING_KEYCHAIN}" \
  | grep -qi "${SIGNING_CERTIFICATE_SHA1}"; then
  echo "Could not find the Vela code-signing identity" >&2
  exit 1
fi
SIGNING_IDENTITY="${SIGNING_CERTIFICATE_SHA1}"
cat > "${SIGNING_SOURCE}" <<EOF
public enum PeerSigningIdentity {
    public static let certificateHash = "${SIGNING_CERTIFICATE_SHA1}"
    public static let appRequirement = "identifier \"com.vela.peer\" and certificate leaf = H\"${SIGNING_CERTIFICATE_SHA1}\""
    public static let helperRequirement = "identifier \"com.vela.peer.helper\" and certificate leaf = H\"${SIGNING_CERTIFICATE_SHA1}\""
}
EOF

swift build --package-path "${PACKAGE_DIR}" --scratch-path "${BUILD_DIR}/swift-arm64" \
  --triple arm64-apple-macosx13.0 --configuration release --product VelaPeer
swift build --package-path "${PACKAGE_DIR}" --scratch-path "${BUILD_DIR}/swift-arm64" \
  --triple arm64-apple-macosx13.0 --configuration release --product VelaPeerHelper
swift build --package-path "${PACKAGE_DIR}" --scratch-path "${BUILD_DIR}/swift-x86_64" \
  --triple x86_64-apple-macosx13.0 --configuration release --product VelaPeer
swift build --package-path "${PACKAGE_DIR}" --scratch-path "${BUILD_DIR}/swift-x86_64" \
  --triple x86_64-apple-macosx13.0 --configuration release --product VelaPeerHelper

APP_BUNDLE="${DIST_DIR}/Vela.app"
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS" \
  "${APP_BUNDLE}/Contents/Library/LaunchDaemons"
lipo -create \
  "${BUILD_DIR}/swift-arm64/release/VelaPeer" \
  "${BUILD_DIR}/swift-x86_64/release/VelaPeer" \
  -output "${APP_BUNDLE}/Contents/MacOS/VelaPeer"
lipo -create \
  "${BUILD_DIR}/swift-arm64/release/VelaPeerHelper" \
  "${BUILD_DIR}/swift-x86_64/release/VelaPeerHelper" \
  -output "${APP_BUNDLE}/Contents/MacOS/VelaPeerHelper"
sed -e "s/__APP_VERSION__/${APP_VERSION}/g" \
    -e "s/__BUILD_VERSION__/${BUILD_VERSION}/g" \
    "${SCRIPT_DIR}/Resources/Info.plist" \
    > "${APP_BUNDLE}/Contents/Info.plist"
cp "${SCRIPT_DIR}/Resources/com.vela.peer.helper.plist" \
  "${APP_BUNDLE}/Contents/Library/LaunchDaemons/com.vela.peer.helper.plist"

codesign --force --timestamp=none --sign "${SIGNING_IDENTITY}" \
  --keychain "${SIGNING_KEYCHAIN}" --identifier com.vela.peer.helper \
  "${APP_BUNDLE}/Contents/MacOS/VelaPeerHelper"
codesign --force --timestamp=none --sign "${SIGNING_IDENTITY}" \
  --keychain "${SIGNING_KEYCHAIN}" --identifier com.vela.peer "${APP_BUNDLE}"
codesign --verify --deep --strict "${APP_BUNDLE}"

ditto -c -k --keepParent "${APP_BUNDLE}" "${DIST_DIR}/Vela-macos-universal.zip"
(
  cd "${DIST_DIR}"
  shasum -a 256 Vela-macos-universal.zip > Vela-macos-universal.zip.sha256
)
