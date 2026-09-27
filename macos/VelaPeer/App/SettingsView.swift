import AppKit
import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmingUninstall = false
    @State private var confirmingDelete = false

    var body: some View {
        Form {
            Section("Startup") {
                Toggle("Open Vela and start the peer at login", isOn: Binding(
                    get: { model.launchAtLogin },
                    set: { value in
                        do { try model.updateLaunchAtLogin(value) }
                        catch { model.alertMessage = error.localizedDescription }
                    }
                ))
                Text("Off by default. When enabled, Vela opens after login and starts the registered peer.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Helper") {
                LabeledContent("Service status", value: helperStatus)
                if model.helperApprovalNeeded {
                    Button("Open Login Items settings") {
                        SMAppService.openSystemSettingsLoginItems()
                    }
                }
            }

            Section("Updates") {
                Text("Updates are installed manually. Vela can check GitHub for a newer release; download it, quit this copy, wait a moment for the helper to exit, and replace Vela.app. Local device data stays in Application Support.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button {
                    Task { await model.checkForUpdates() }
                } label: {
                    if model.isCheckingForUpdates {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Check for updates")
                    }
                }
                .disabled(model.isCheckingForUpdates)
            }

            Section("Local data") {
                Text("Peer settings: \(PeerFiles.directory.path)")
                    .font(.caption)
                    .textSelection(.enabled)
                Button("Prepare to uninstall…") { confirmingUninstall = true }
                    .disabled(model.isPeerActionBusy)
                Button("Delete device data…", role: .destructive) { confirmingDelete = true }
                    .disabled(model.isPeerActionBusy)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520, height: 470)
        .confirmationDialog(
            "Prepare Vela for uninstall?",
            isPresented: $confirmingUninstall,
            titleVisibility: .visible
        ) {
                Button("Keep device data and unregister helper") {
                    Task {
                        do {
                            try await model.prepareForUninstall()
                        } catch {
                            model.alertMessage = error.localizedDescription
                        }
                    }
                }
                .disabled(model.isPeerActionBusy)
                Button("Delete device data and unregister helper", role: .destructive) {
                    Task {
                        do {
                            try await model.prepareForUninstall(deleteDeviceData: true)
                        } catch {
                            model.alertMessage = error.localizedDescription
                        }
                    }
                }
                .disabled(model.isPeerActionBusy)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The peer will stop and its helper and login item will be unregistered. Keep device data to continue with this identity after reinstalling, or choose the delete option. Deletion affects only this Mac; an administrator must revoke the Coordinator registration.")
        }
        .confirmationDialog(
            "Delete local device data?",
            isPresented: $confirmingDelete,
            titleVisibility: .visible
        ) {
            Button("Delete local data", role: .destructive) {
                Task {
                    do { try await model.deleteDeviceData() }
                    catch { model.alertMessage = error.localizedDescription }
                }
            }
            .disabled(model.isPeerActionBusy)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the local identity, credential, peer settings, and logs. The Coordinator registration remains; its administrator must revoke it separately.")
        }
        .alert("Vela Peer", isPresented: Binding(
            get: { model.alertMessage != nil },
            set: { if !$0 { model.alertMessage = nil } }
        )) {
            Button("OK") { model.alertMessage = nil }
            if let url = model.updateReleaseURL {
                Button("Download update") {
                    NSWorkspace.shared.open(url)
                    model.alertMessage = nil
                }
            }
        } message: {
            Text(model.alertMessage ?? "")
        }
    }

    private var helperStatus: String {
        switch SMAppService.daemon(plistName: "com.vela.peer.helper.plist").status {
        case .enabled: "Enabled"
        case .requiresApproval: "Waiting for approval"
        case .notRegistered: "Not registered"
        case .notFound: "Missing from app bundle"
        @unknown default: "Unknown"
        }
    }
}
