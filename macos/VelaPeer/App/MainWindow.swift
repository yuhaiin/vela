import AppKit
import SwiftUI

struct MainWindow: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if model.hasRegistration {
                    registeredPeer
                    if let error = model.startErrorMessage {
                        Label("Could not start peer: \(error)", systemImage: "exclamationmark.triangle")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                    }
                    if let error = model.stopErrorMessage {
                        Label("Could not stop peer: \(error)", systemImage: "exclamationmark.triangle")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                    }
                    DisclosureGroup("Register again or change Coordinator") {
                        RegistrationCard()
                            .padding(.top, 12)
                    }
                    .padding(16)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))
                } else {
                    RegistrationCard()
                }

                DisclosureGroup("Diagnostics") {
                    VStack(alignment: .leading, spacing: 10) {
                        diagnosticFacts
                        ScrollView {
                            Text(model.dashboardJSON)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(10)
                        }
                        .frame(height: 220)
                        .background(.background, in: RoundedRectangle(cornerRadius: 8))
                    }
                    .padding(.top, 10)
                }
                .padding(16)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))

                DisclosureGroup("Logs") {
                    ScrollView {
                        Text(model.logs.isEmpty ? "No app events yet." : model.logs.joined(separator: "\n"))
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    .frame(height: 160)
                    .background(.background, in: RoundedRectangle(cornerRadius: 8))
                    HStack {
                        Text(PeerFiles.log.path)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .textSelection(.enabled)
                        Spacer()
                        Button("Copy logs") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(model.logs.joined(separator: "\n"), forType: .string)
                        }
                    }
                    .padding(.top, 8)
                }
                .padding(16)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))
            }
            .padding(22)
        }
        .frame(minWidth: 560, minHeight: 560)
        .alert("Vela Peer", isPresented: Binding(
            get: { model.alertMessage != nil },
            set: { if !$0 { model.alertMessage = nil } }
        )) {
            Button("OK") { model.alertMessage = nil }
        } message: {
            Text(model.alertMessage ?? "")
        }
        .task { await model.refreshStatus() }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "network")
                .font(.system(size: 28, weight: .medium))
                .foregroundStyle(.tint)
                .frame(width: 52, height: 52)
                .background(.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 4) {
                Text("Vela Peer").font(.title2.weight(.semibold))
                Text("\(model.isRunning ? "Running" : model.hasRegistration ? "Registered" : "Not registered") · This Mac")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.hasRegistration {
                Button {
                    Task { await togglePeer() }
                } label: {
                    if model.isStarting || model.isStopping { ProgressView().controlSize(.small) }
                    else { Text(model.isRunning ? "Stop" : "Start") }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isPeerActionBusy || (!model.isRunning && model.secretsUnavailable))
            }
        }
    }

    private var registeredPeer: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Circle()
                    .fill(model.isRunning ? (model.coordinatorConnected == true ? .green : .orange) : .secondary)
                    .frame(width: 9, height: 9)
                Text(model.isRunning ? connectionStatus : "Registered")
                    .font(.headline)
                Spacer()
                if model.isRunning { Text("\(model.peerCount) peers").foregroundStyle(.secondary) }
            }
            LabeledContent("Coordinator", value: model.coordinatorURL)
                .textSelection(.enabled)
            LabeledContent("Public key fingerprint", value: model.coordinatorFingerprint)
                .textSelection(.enabled)
            if let nodeID = model.nodeID {
                LabeledContent("Device ID", value: nodeID)
                    .textSelection(.enabled)
            }
            if let tunName = model.tunName {
                LabeledContent("TUN interface", value: tunName)
            }
            if !model.isRunning {
                Text("Registration is saved. Start the peer when you are ready to connect.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))
    }

    private var diagnosticFacts: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent("Coordinator connection", value: connectionStatus)
            if let nodeID = model.nodeID { LabeledContent("Node ID", value: nodeID) }
            if let tunName = model.tunName { LabeledContent("TUN", value: tunName) }
            LabeledContent("Known peers", value: "\(model.peerCount)")
        }
        .font(.callout)
    }

    private var connectionStatus: String {
        guard model.isRunning else { return "Stopped" }
        switch model.coordinatorConnected {
        case .some(true): return "Connected"
        case .some(false): return "Reconnecting"
        case .none: return "Starting"
        }
    }

    private func togglePeer() async {
        if model.isRunning {
            await model.stopPeer()
        } else {
            do { try await model.startPeer() }
            catch { model.alertMessage = error.localizedDescription }
        }
    }
}

private struct RegistrationCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingScanner = false
    @State private var confirmingReplacement = false
    @State private var isRegistering = false
    @State private var submittedBundle: RegistrationBundle?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(model.hasRegistration ? "Register with an invite" : "Connect this Mac")
                .font(.headline)
            Text("Paste the registration bundle from the Coordinator admin page, or scan its QR code.")
                .font(.callout)
                .foregroundStyle(.secondary)

            TextEditor(text: $model.registrationText)
                .font(.system(.body, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(6)
                .frame(minHeight: 110, maxHeight: 150)
                .background(.background, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary))

            HStack {
                Button("Paste") {
                    if let text = NSPasteboard.general.string(forType: .string) {
                        model.registrationText = text
                    }
                }
                Button("Scan QR Code") { showingScanner = true }
                Spacer()
                Button {
                    guard let bundle = model.registrationPreview else { return }
                    submittedBundle = bundle
                    if model.replacesCoordinator {
                        confirmingReplacement = true
                    } else {
                        Task { await submit(bundle) }
                    }
                } label: {
                    if isRegistering { ProgressView().controlSize(.small) }
                    else { Text("Register peer") }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.registrationPreview == nil || isRegistering || model.isPeerActionBusy)
            }

            if let error = model.registrationError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            if let bundle = model.registrationPreview {
                Divider()
                Text("Confirm Coordinator").font(.subheadline.weight(.semibold))
                LabeledContent("Address", value: bundle.coordinator.url)
                    .textSelection(.enabled)
                LabeledContent("Public key fingerprint", value: bundle.fingerprint)
                    .textSelection(.enabled)
                Text("The one-time invite is submitted only after you choose Register peer.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))
        .confirmationDialog(
            "Replace the active Coordinator?",
            isPresented: $confirmingReplacement,
            titleVisibility: .visible
        ) {
            Button("Replace Coordinator", role: .destructive) {
                if let submittedBundle { Task { await submit(submittedBundle) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Vela will reuse this Mac's identity. Its registration on the old Coordinator will remain and must be revoked by that Coordinator's administrator.")
        }
        .sheet(isPresented: $showingScanner) {
            QRScannerSheet { text in
                model.registrationText = text
                showingScanner = false
            }
            .frame(width: 480, height: 420)
        }
    }

    private func submit(_ bundle: RegistrationBundle) async {
        isRegistering = true
        defer { isRegistering = false }
        do {
            try await model.register(bundle)
        } catch {
            model.alertMessage = error.localizedDescription
        }
    }
}
