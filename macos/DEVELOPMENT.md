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

## Mac validation checklist

These checks require a Mac; a successful CI build does not prove how macOS handles helper approval, TUN permissions, routes, or camera access. Run them on macOS 13 or later with a staging Coordinator and disposable peer registrations. Cover both Apple Silicon and Intel before calling the Universal build ready. Record the Mac model, macOS version, app commit, and pass/fail result, but do not include invite packages, private keys, or credentials in screenshots or logs.

For an Actions preview, download the app archive and its checksum from the same workflow run, then verify it before opening:

```sh
shasum -a 256 -c Vela-macos-universal.zip.sha256
```

The preview is signed with a temporary self-signed certificate and is not notarized. Only use the Gatekeeper override described in [README.md](README.md) after confirming the download came from the Vela repository and its checksum matches.

### First launch and registration

- [ ] Launch Vela with no saved peer. Confirm the menu bar item appears and the app does not start a peer or request TUN access.
- [ ] Open and close the main window. Confirm the menu bar app stays available and can reopen the window.
- [ ] Create a disposable registration package on the staging Coordinator. Paste it into Vela and confirm the displayed Coordinator address and public-key fingerprint match the admin page.
- [ ] Cancel registration and confirm the peer remains unregistered. Use a fresh one-time invite, submit it, and confirm the app shows **Registered** without starting the peer.
- [ ] Repeat registration using a fresh QR invite and grant camera access when prompted. Confirm the preview matches the pasted-package flow.
- [ ] Confirm the identity and credential are stored in Keychain and peer files are under `~/Library/Application Support/Vela/peer`. Do not inspect or copy secret values into test notes.

### Helper approval and peer lifecycle

- [ ] Select **Start** explicitly. Approve Vela Peer Helper in Login Items if macOS asks. Confirm the peer starts, the TUN interface appears, and the UI reports Coordinator/peer status.
- [ ] Select **Stop**. Confirm the peer stops and Vela removes its TUN interface and routes.
- [ ] Start again, close the main window, then reopen it from the menu bar. Confirm the peer stayed running.
- [ ] Stop from the menu bar. Start again and choose **Quit Vela** from the menu bar context menu. Confirm the peer stops, routes are removed, and the helper exits.
- [ ] Start the peer again and force-quit the app from Activity Monitor. Confirm the helper notices the disconnected app, stops the peer, removes its TUN interface/routes, and exits. Relaunch Vela and confirm it reports the peer stopped.
- [ ] While running, inspect **Diagnostics** and **Logs**. Confirm status and errors are visible and **Copy logs** works. Check that logs do not contain invite text, private keys, or credentials.

### Login item and Coordinator migration

- [ ] Confirm **Open Vela and start the peer at login** is off by default.
- [ ] Enable it on a disposable account, approve the login item if prompted, log out and back in, and confirm Vela opens and starts the registered peer. Disable it afterward and confirm the peer no longer auto-starts at login.
- [ ] With a peer registered to Coordinator A, enter a package for Coordinator B. Cancel the replacement warning and confirm A remains active. Repeat and confirm replacement; verify the local identity is reused and the UI explains that an administrator must revoke the old Coordinator registration.

### Uninstall, local data, and update

- [ ] Choose **Prepare to uninstall** and keep device data. Confirm the peer stops, helper and login item are unregistered, and local peer data remains. Relaunch the app and confirm it still shows the same registration.
- [ ] On a separate disposable registration, choose **Delete device data**. Confirm only this Mac's peer files and Keychain identity are removed; verify the Coordinator registration still exists until its administrator revokes it.
- [ ] For an update test, use two builds signed with the same persistent release identity. With the peer running, quit Vela, replace `Vela.app`, relaunch, and confirm the helper loads from the new bundle and the saved identity remains usable. This check is not covered by temporary-certificate preview builds.

Keep the observed results with the PR. Any failure in helper approval, abnormal-exit cleanup, route removal, identity retention, or update must be fixed before publishing a release. Choose the release version and create a public tag only after these Mac checks pass.
