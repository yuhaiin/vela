import AppKit
import SwiftUI

@main
struct VelaPeerApp: App {
    @NSApplicationDelegateAdaptor(VelaAppDelegate.self) private var appDelegate
    @StateObject private var model: AppModel

    init() {
        let model = AppModel()
        _model = StateObject(wrappedValue: model)
        VelaAppDelegate.model = model
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent()
                .environmentObject(model)
        } label: {
            Label("Vela", systemImage: model.isRunning ? "network" : "network.slash")
        }
        .menuBarExtraStyle(.menu)

        Window("Vela Peer", id: "main") {
            MainWindow()
                .environmentObject(model)
        }
        .defaultSize(width: 620, height: 720)
        .windowResizability(.contentSize)

        Settings {
            SettingsView()
                .environmentObject(model)
        }
        .commands {
            CommandGroup(replacing: .appTermination) {
                Button("Quit Vela") {
                    model.quit()
                }
                .keyboardShortcut("q")
                .disabled(model.isPeerActionBusy)
            }
        }
    }
}

@MainActor
final class VelaAppDelegate: NSObject, NSApplicationDelegate {
    static weak var model: AppModel?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model = Self.model else { return .terminateNow }
        guard !model.isPeerActionBusy else {
            model.alertMessage = "Wait for the current peer operation to finish before quitting Vela."
            return .terminateCancel
        }
        Task {
            await model.stopPeer()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

private struct MenuBarContent: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Text(statusText)
            .foregroundStyle(.secondary)
        Divider()
        Button("Open Vela Peer") { openWindow(id: "main") }
        if model.hasRegistration {
            if model.isRunning {
                Button("Stop peer") { Task { await model.stopPeer() } }
                    .disabled(model.isPeerActionBusy)
            } else {
                Button("Start peer") { Task { await startPeer() } }
                    .disabled(model.isPeerActionBusy || model.secretsUnavailable)
            }
        }
        Button("Settings…") { openSettings() }
        Divider()
        Button("Quit Vela") { model.quit() }
            .disabled(model.isPeerActionBusy)
    }

    private var quickStatus: String {
        if model.coordinatorConnected == true { return "Connected · \(model.peerCount) peers" }
        if model.coordinatorConnected == false { return "Reconnecting to Coordinator" }
        return "Starting peer…"
    }

    private var statusText: String {
        if model.isRegistering { return "Registering peer…" }
        if model.isStopping { return "Stopping peer…" }
        if model.isStarting { return "Starting peer…" }
        if model.stopErrorMessage != nil { return "Peer stop failed · Open Vela Peer for details" }
        if model.isRunning { return quickStatus }
        if let error = model.startErrorMessage { return "Peer start failed · \(error)" }
        return model.hasRegistration ? "Registered" : "Not registered"
    }

    private func startPeer() async {
        do { try await model.startPeer() }
        catch { model.alertMessage = error.localizedDescription }
    }
}
