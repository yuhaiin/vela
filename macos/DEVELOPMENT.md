# macOS app build notes

## Build

Build the universal app on macOS with Xcode Command Line Tools, Swift, Rust, and the `aarch64-apple-darwin` and `x86_64-apple-darwin` Rust targets. The build currently uses macOS 13 as a provisional deployment floor because `SMAppService` was introduced there; confirm or raise that floor after validating the helper and TUN lifecycle on the oldest supported Mac:

```sh
bash macos/VelaPeer/build-app.sh
```

Linux cross-compilation with [OSXCross](https://github.com/tpoechtrager/osxcross) can help build Rust/C dependencies, but it requires a macOS SDK extracted from Xcode or the Command Line Tools. It does not replace Apple's Swift toolchain or validate SwiftUI, `SMAppService`, or the TUN/helper lifecycle. Use the [macOS app workflow](../.github/workflows/macos-app.yml) to build the app bundle on a macOS runner.

The script makes a temporary self-signed code-signing identity when no persistent identity is configured. The app and privileged helper use that certificate fingerprint to authenticate their XPC connection. The private key is removed when the build exits.

## Stable identity for releases

Public release tags require one persistent self-signed code-signing identity. Reusing it keeps the XPC trust requirement and macOS Keychain app identity stable across updates. Create a certificate with the Code Signing extended key usage, export it as PKCS#12, and configure these repository Actions secrets:

- `VELA_MACOS_SIGNING_P12_BASE64`: base64-encoded PKCS#12 file
- `VELA_MACOS_SIGNING_P12_PASSWORD`: the PKCS#12 export password

Generate one outside the repository with OpenSSL, then reuse the same PKCS#12 file for every release:

```sh
umask 077
mkdir -p "$HOME/.config"
SIGNING_DIR="$(mktemp -d "$HOME/.config/vela-release-signing.XXXXXX")"
cat > "$SIGNING_DIR/openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = code_signing
prompt = no

[subject]
CN = Vela Peer Release Signing

[code_signing]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -config "$SIGNING_DIR/openssl.cnf" \
  -keyout "$SIGNING_DIR/private-key.pem" \
  -out "$SIGNING_DIR/certificate.pem"
openssl pkcs12 -export \
  -inkey "$SIGNING_DIR/private-key.pem" \
  -in "$SIGNING_DIR/certificate.pem" \
  -name "Vela Peer Release Signing" \
  -out "$SIGNING_DIR/identity.p12"
base64 < "$SIGNING_DIR/identity.p12" > "$SIGNING_DIR/identity.p12.base64"
chmod 600 "$SIGNING_DIR/identity.p12" "$SIGNING_DIR/identity.p12.base64"
rm "$SIGNING_DIR/private-key.pem" "$SIGNING_DIR/certificate.pem" "$SIGNING_DIR/openssl.cnf"
printf 'Signing files saved in %s\n' "$SIGNING_DIR"
```

Open `identity.p12.base64` and copy its contents into the first Actions secret. The password entered during PKCS#12 export goes into the second secret. Keep the encrypted `identity.p12` backup and its password in a secure place; do not commit either file.

Keep the private key out of the repository. Pull request builds use a temporary certificate; tagged release builds fail if the persistent secrets are missing. A self-signed certificate does not require a paid Apple Developer Program membership, but it also does not provide Apple notarization or Gatekeeper approval. Users may still need to approve the download in Privacy & Security.

## Release

After Mac validation and choosing the release version, push a `v`-prefixed numeric tag (`v<major>.<minor>.<patch>`). The workflow builds the universal zip, publishes it with a SHA-256 checksum, and uses this directory's `README.md` as the release notes. The app version comes from the tag.

## Mac validation still required

Run the app on macOS 13 or later and verify first launch, Camera permission, LaunchDaemon registration and approval, TUN creation, route cleanup, peer stop after app termination, helper exit and relaunch after an app update, launch-at-login, and local-data deletion. The helper should stop the peer and exit when its app client disconnects, so the next launch loads the helper from the current app bundle. The Linux development environment cannot validate these macOS system behaviors.
