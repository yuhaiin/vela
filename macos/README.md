# Vela Peer for macOS

The macOS app is a universal menu bar app for Apple Silicon and Intel Macs. The current build candidate targets macOS 13 or later because the chosen `SMAppService` API starts there. Confirm the final minimum after validating the helper and TUN lifecycle on a clean Mac before publishing a release.

## Install

Download `Vela-macos-universal.zip` and its `.sha256` file from the Vela GitHub release. Verify the archive before opening it:

```sh
shasum -a 256 -c Vela-macos-universal.zip.sha256
```

Unzip `Vela.app`, move it to `/Applications`, then open it. The app is signed with a self-signed certificate and is not notarized with Apple. macOS may block the first launch; after attempting to open it, use **System Settings > Privacy & Security > Open Anyway** only if the package came from the official Vela release and its checksum matches. See [Apple's instructions for opening an app from an unidentified developer](https://support.apple.com/en-us/102445).

The first time you start a peer, macOS asks you to approve the Vela Peer Helper in **System Settings > General > Login Items**. The helper needs administrator approval to manage the TUN interface and routes. The optional “Open Vela and start the peer at login” setting is off by default.

## Register a peer

In the Coordinator admin page, create an invite and show the registration QR code, copy the JSON package, or download it. In Vela Peer, scan the QR code or paste the package. Confirm the Coordinator address and public key fingerprint before submitting the one-time invite. Registration does not start the peer; press **Start** when ready.

## Data and removal

The app stores ordinary settings in `~/Library/Application Support/Vela/settings.json`, and peer configuration and logs in `~/Library/Application Support/Vela/peer`. Identity keys and registration credentials are stored in Keychain. Replacing or removing the app keeps this data by default.

Before uninstalling, choose **Prepare to uninstall** in Settings to stop the peer and unregister the helper and login item. **Delete device data** removes only this Mac's files and Keychain item. The peer registration on the Coordinator remains and must be revoked by its administrator.

Updates are installed manually. Use **Check for updates** in Settings to open the latest release when one is available. Before replacing Vela.app, quit the app and allow its helper to exit.
