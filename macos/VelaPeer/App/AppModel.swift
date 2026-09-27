import AppKit
import Foundation
import ServiceManagement
import SwiftUI
import VelaPeerShared

@MainActor
final class AppModel: ObservableObject {
    @Published var registrationText = "" {
        didSet { parseRegistrationText() }
    }
    @Published private(set) var registrationPreview: RegistrationBundle?
    @Published private(set) var registrationError: String?
    @Published private(set) var configJSON: Data?
    @Published private(set) var isRunning = false
    @Published private(set) var isStarting = false
    @Published private(set) var isRegistering = false
    @Published private(set) var isStopping = false
    @Published private(set) var startErrorMessage: String?
    @Published private(set) var stopErrorMessage: String?
    @Published private(set) var coordinatorConnected: Bool?
    @Published private(set) var nodeID: String?
    @Published private(set) var tunName: String?
    @Published private(set) var peerCount = 0
    @Published private(set) var dashboardJSON = "No peer diagnostics are available."
    @Published private(set) var logs: [String] = []
    @Published var launchAtLogin: Bool
    @Published var alertMessage: String?
    @Published private(set) var isCheckingForUpdates = false
    @Published private(set) var updateReleaseURL: URL?

    private var settings: VelaAppSettings
    private var secrets: ActivePeerSecrets?
    private var helperClient: PeerHelperClient?
    private var monitorTask: Task<Void, Never>?
    private var lastCoordinatorError: String?
    private var lastHelperStatusError: String?
    private let helperService = SMAppService.daemon(plistName: "com.vela.peer.helper.plist")

    init() {
        do {
            settings = try PeerFiles.loadSettings()
            launchAtLogin = settings.launchAtLogin
        } catch {
            settings = VelaAppSettings()
            launchAtLogin = false
            alertMessage = "Could not load Vela settings: \(error.localizedDescription)"
        }
        loadLocalState()
        loadLogs()
        if launchAtLogin, hasRegistration {
            Task { try? await startPeer() }
        }
    }

    var hasRegistration: Bool {
        guard let configJSON,
              let secrets,
              secrets.hasValidIdentity,
              !secrets.credential.isEmpty,
              savedCoordinator(from: configJSON) != nil
        else { return false }
        return true
    }

    var secretsUnavailable: Bool {
        guard let secrets else { return true }
        return !secrets.hasValidIdentity || secrets.credential.isEmpty
    }

    var coordinatorURL: String {
        guard let configJSON else { return "" }
        return savedCoordinator(from: configJSON)?.url ?? ""
    }

    var coordinatorFingerprint: String {
        guard let configJSON,
              let coordinator = savedCoordinator(from: configJSON)
        else { return "" }
        return coordinatorKeyFingerprint(coordinator.publicKey)
    }

    var replacesCoordinator: Bool {
        guard let registrationPreview,
              let configJSON,
              let current = savedCoordinator(from: configJSON),
              let incomingKey = Data(base64Encoded: registrationPreview.coordinator.publicKey)
        else { return false }
        return normalizedCoordinatorURL(current.url) != normalizedCoordinatorURL(registrationPreview.coordinator.url)
            || current.publicKey != incomingKey
    }

    var helperApprovalNeeded: Bool {
        helperService.status == .requiresApproval
    }

    var isPeerActionBusy: Bool {
        isStarting || isRegistering || isStopping
    }

    func register(_ bundle: RegistrationBundle) async throws {
        guard !isStarting, !isRegistering, !isStopping else {
            throw PeerAppError.helperUnavailable("Wait for the current peer operation to finish before registering again.")
        }
        isRegistering = true
        defer { isRegistering = false }
        if isRunning {
            try await stopPeerAndConfirm(allowDuringRegistration: true)
        }
        let oldConfig = configJSON
        let oldSecrets = try VelaKeychain.load()
        if let oldSecrets, !oldSecrets.hasValidIdentity {
            throw PeerAppError.incompleteKeychainIdentity
        }
        if let oldConfig {
            guard let oldSecrets, oldSecrets.hasValidIdentity, !oldSecrets.credential.isEmpty else {
                throw PeerAppError.incompleteKeychainIdentity
            }
            guard savedCoordinator(from: oldConfig) != nil else {
                throw PeerAppError.invalidSavedPeerSettings
            }
        } else if let oldSecrets, !oldSecrets.credential.isEmpty {
            throw PeerAppError.peerSettingsMissing
        }
        let identity: ActivePeerSecrets
        if let oldSecrets {
            identity = oldSecrets
        } else {
            let generated = try await Task.detached(priority: .userInitiated) {
                try RustBridge.generateIdentity()
            }.value
            identity = ActivePeerSecrets(
                signingPrivate: generated.signingPrivate,
                noisePrivate: generated.noisePrivate,
                credential: Data()
            )
            // Save the device identity before consuming the one-time invite.
            // If the Coordinator accepts the invite but local persistence
            // later fails, a fresh invite can still reuse this identity.
            try VelaKeychain.save(identity)
        }

        let peerConfig = try RustBridge.createConfig(
            server: bundle.coordinator.url,
            publicKey: bundle.coordinator.publicKey
        )
        let result = try await Task.detached(priority: .userInitiated) {
            try RustBridge.register(
                config: peerConfig,
                identity: identity.identityMaterial,
                invite: bundle.invite
            )
        }.value

        let updatedSecrets = ActivePeerSecrets(
            signingPrivate: identity.signingPrivate,
            noisePrivate: identity.noisePrivate,
            credential: result.credential
        )
        try VelaKeychain.save(updatedSecrets)
        do {
            try PeerFiles.saveConfig(result.config)
        } catch {
            try? VelaKeychain.save(oldSecrets ?? ActivePeerSecrets(
                signingPrivate: identity.signingPrivate,
                noisePrivate: identity.noisePrivate,
                credential: Data()
            ))
            if let oldConfig { try? PeerFiles.saveConfig(oldConfig) }
            throw error
        }

        secrets = updatedSecrets
        configJSON = result.config
        registrationText = ""
        registrationError = nil
        startErrorMessage = nil
        appendLog("Registered with \(bundle.coordinator.url)")
    }

    func startPeer() async throws {
        guard !isPeerActionBusy else { return }
        isStarting = true
        startErrorMessage = nil
        stopErrorMessage = nil
        defer { isStarting = false }
        do {
            guard let configJSON, let secrets else { throw PeerAppError.noRegistration }
            try ensureHelperRegistered()

            let request = try makeServiceRequest(config: configJSON, secrets: secrets)
            let client = helperClient ?? makeHelperClient()
            do {
                let response = try await client.startPeer(request)
                helperClient = client
                applyHelperStatus(response)
                appendLog("Started peer on \(tunName ?? "TUN")")
                startMonitoring()
            } catch {
                client.invalidate()
                if helperClient === client { helperClient = nil }
                throw error
            }
        } catch {
            startErrorMessage = error.localizedDescription
            appendLog("Could not start peer: \(error.localizedDescription)")
            throw error
        }
    }

    func stopPeer() async {
        do {
            try await stopPeerAndConfirm()
            stopErrorMessage = nil
        } catch {
            stopErrorMessage = error.localizedDescription
            appendLog("Peer stop error: \(error.localizedDescription)")
        }
    }

    private func stopPeerAndConfirm(
        confirmHelperState: Bool = false,
        allowDuringRegistration: Bool = false
    ) async throws {
        guard !isStarting else {
            throw PeerAppError.helperUnavailable("Wait for peer startup to finish before stopping it.")
        }
        guard allowDuringRegistration || !isRegistering else {
            throw PeerAppError.helperUnavailable("Wait for registration to finish before stopping the peer.")
        }
        guard !isStopping else {
            throw PeerAppError.helperUnavailable("The peer is already stopping.")
        }
        isStopping = true
        defer { isStopping = false }
        monitorTask?.cancel()
        monitorTask = nil

        let client: PeerHelperClient?
        let queryStatusFirst: Bool
        if let helperClient {
            client = helperClient
            queryStatusFirst = false
        } else if isRunning || confirmHelperState {
            switch helperService.status {
            case .enabled:
                let connectedClient = makeHelperClient()
                helperClient = connectedClient
                client = connectedClient
                queryStatusFirst = true
            case .notRegistered where !isRunning:
                client = nil
                queryStatusFirst = false
            case .requiresApproval where !isRunning:
                client = nil
                queryStatusFirst = false
            case .notFound:
                throw PeerAppError.helperUnavailable("the helper is missing, so Vela cannot confirm that the peer has stopped")
            case .notRegistered, .requiresApproval:
                throw PeerAppError.helperUnavailable("the helper is unavailable, so Vela cannot confirm that the peer has stopped")
            @unknown default:
                throw PeerAppError.helperUnavailable("the helper has an unknown status")
            }
        } else {
            client = nil
            queryStatusFirst = false
        }

        do {
            if let client {
                if queryStatusFirst {
                    let status = try await client.peerStatus()
                    if try helperReportsRunning(status) {
                        try await client.stopPeer()
                    }
                } else {
                    try await client.stopPeer()
                }
            }
        } catch {
            if isRunning { startMonitoring() }
            throw error
        }

        isRunning = false
        coordinatorConnected = nil
        if let client {
            client.invalidate()
            if helperClient === client {
                helperClient = nil
            }
        }
        appendLog("Stopped peer")
    }

    private func helperReportsRunning(_ data: Data) throws -> Bool {
        guard let status = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PeerAppError.helperUnavailable("the helper returned invalid peer status")
        }
        if let error = status["error"] as? String {
            throw PeerAppError.helperUnavailable(error)
        }
        guard let running = status["running"] as? Bool else {
            throw PeerAppError.helperUnavailable("the helper status did not include a running state")
        }
        return running
    }

    func quit() {
        NSApplication.shared.terminate(nil)
    }

    func updateLaunchAtLogin(_ enabled: Bool) throws {
        let service = SMAppService.mainApp
        if enabled {
            if service.status == .notRegistered {
                do {
                    try service.register()
                } catch {
                    guard service.status == .requiresApproval else { throw error }
                }
            }
            if service.status == .requiresApproval {
                SMAppService.openSystemSettingsLoginItems()
                settings.launchAtLogin = true
                try PeerFiles.saveSettings(settings)
                launchAtLogin = true
                alertMessage = PeerAppError.loginItemApprovalRequired.localizedDescription
                return
            }
            guard service.status == .enabled else {
                throw PeerAppError.loginItemUnavailable("the Vela login item could not be registered")
            }
        } else if service.status != .notRegistered {
            try service.unregister()
        }
        settings.launchAtLogin = enabled
        try PeerFiles.saveSettings(settings)
        launchAtLogin = enabled
    }

    func checkForUpdates() async {
        guard !isCheckingForUpdates else { return }
        isCheckingForUpdates = true
        updateReleaseURL = nil
        defer { isCheckingForUpdates = false }

        do {
            var request = URLRequest(url: URL(string: "https://api.github.com/repos/yuhaiin/vela/releases/latest")!)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            request.setValue("VelaPeer/\(currentVersion)", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let response = response as? HTTPURLResponse,
                  (200..<300).contains(response.statusCode)
            else {
                throw PeerAppError.rust("GitHub did not return a published Vela release.")
            }
            let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
            guard let url = URL(string: release.htmlURL) else {
                throw PeerAppError.rust("The latest Vela release has an invalid download page.")
            }

            if let current = versionComponents(currentVersion),
               let latest = versionComponents(release.tagName),
               compareVersions(latest, current) <= 0
            {
                alertMessage = "Vela is up to date (\(currentVersion))."
                return
            }

            updateReleaseURL = url
            alertMessage = "Vela \(release.tagName) is available. Download the update and replace Vela.app manually."
        } catch {
            alertMessage = "Could not check for updates: \(error.localizedDescription)"
        }
    }

    func prepareForUninstall(deleteDeviceData: Bool = false) async throws {
        try await stopPeerAndConfirm(confirmHelperState: true)
        if helperService.status != .notRegistered {
            try await helperService.unregister()
        }
        if SMAppService.mainApp.status != .notRegistered {
            try await SMAppService.mainApp.unregister()
        }
        settings.helperSigningCertificate = nil
        settings.launchAtLogin = false
        try PeerFiles.saveSettings(settings)
        launchAtLogin = false
        if deleteDeviceData {
            try clearDeviceData()
            alertMessage = "Vela helper and login item were unregistered. Local device data was deleted. The Coordinator registration remains and must be revoked by its administrator. Quit Vela before removing Vela.app."
        } else {
            appendLog("Unregistered Vela helper; local device data was kept")
            alertMessage = "Vela helper and login item were unregistered. Local device data was kept. Quit Vela before removing Vela.app."
        }
    }

    func deleteDeviceData() async throws {
        try await stopPeerAndConfirm(confirmHelperState: true)
        try clearDeviceData()
        alertMessage = "Local device data was deleted. The peer registration still exists on the Coordinator; ask its administrator to revoke it."
    }

    private func clearDeviceData() throws {
        try PeerFiles.removeLocalData()
        secrets = nil
        configJSON = nil
        nodeID = nil
        coordinatorConnected = nil
        peerCount = 0
        dashboardJSON = "No peer diagnostics are available."
        logs = []
        registrationText = ""
        registrationError = nil
        startErrorMessage = nil
        lastCoordinatorError = nil
        lastHelperStatusError = nil
    }

    func refreshStatus() async {
        guard let helperClient else { return }
        do {
            applyHelperStatus(try await helperClient.peerStatus())
        } catch {
            let message = error.localizedDescription
            if message != lastHelperStatusError {
                appendLog("Status request failed: \(message)")
                lastHelperStatusError = message
            }
        }
    }

    private func ensureHelperRegistered() throws {
        let signingHash = PeerSigningIdentity.certificateHash
        let registeredHash = settings.helperSigningCertificate
        if registeredHash != signingHash,
           (helperService.status == .enabled || helperService.status == .requiresApproval)
        {
            try helperService.unregister()
        }
        if registeredHash != signingHash {
            settings.helperSigningCertificate = signingHash
            try PeerFiles.saveSettings(settings)
        }

        switch helperService.status {
        case .enabled:
            return
        case .notRegistered:
            do {
                try helperService.register()
            } catch {
                guard helperService.status == .requiresApproval else { throw error }
            }
        case .requiresApproval:
            SMAppService.openSystemSettingsLoginItems()
            throw PeerAppError.helperApprovalRequired
        case .notFound:
            throw PeerAppError.helperUnavailable("the daemon plist is missing from the app bundle")
        @unknown default:
            throw PeerAppError.helperUnavailable("unknown Service Management status")
        }
        if helperService.status != .enabled {
            SMAppService.openSystemSettingsLoginItems()
            throw PeerAppError.helperApprovalRequired
        }
    }

    private func makeHelperClient() -> PeerHelperClient {
        let client = PeerHelperClient()
        client.onDisconnect = { [weak self, weak client] in
            guard let self, let client, self.helperClient === client else { return }
            self.helperClient = nil
            self.stopMonitoring()
            guard self.isRunning else { return }
            self.isRunning = false
            self.coordinatorConnected = nil
            self.appendLog("Helper connection ended; peer stopped")
        }
        return client
    }

    private func makeServiceRequest(config: Data, secrets: ActivePeerSecrets) throws -> Data {
        guard let peerObject = try JSONSerialization.jsonObject(with: config) as? [String: Any],
              let credentialObject = try JSONSerialization.jsonObject(with: secrets.credential) as? [String: Any]
        else {
            throw PeerAppError.rust("Saved peer settings are invalid.")
        }
        let request: [String: Any] = [
            "state_dir": PeerFiles.directory.path,
            "peer": peerObject,
            "secrets": [
                "signing_private": secrets.signingPrivate.base64EncodedString(),
                "noise_private": secrets.noisePrivate.base64EncodedString(),
                "credential": credentialObject,
            ],
            "port": NSNull(),
            "mtu": 1200,
            "tun_name": "",
        ]
        return try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
    }

    private func startMonitoring() {
        monitorTask?.cancel()
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled else { return }
                await self?.refreshStatus()
            }
        }
    }

    private func stopMonitoring() {
        monitorTask?.cancel()
        monitorTask = nil
    }

    private func applyHelperStatus(_ data: Data) {
        guard let status = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        isRunning = status["running"] as? Bool ?? false
        if !isRunning { stopMonitoring() }
        nodeID = status["node_id"] as? String
        tunName = status["tun_name"] as? String

        if let dashboard = status["dashboard"] as? [String: Any] {
            let coordinator = dashboard["coordinator"] as? [String: Any]
            coordinatorConnected = coordinator?["connected"] as? Bool
            let peers = dashboard["peers"] as? [Any] ?? []
            peerCount = peers.count
            if let encoded = try? JSONSerialization.data(withJSONObject: dashboard, options: [.prettyPrinted, .sortedKeys]) {
                dashboardJSON = String(decoding: encoded, as: UTF8.self)
            }
            if let lastError = coordinator?["last_error"] as? String {
                if lastError != lastCoordinatorError {
                    appendLog("Coordinator: \(lastError)")
                    lastCoordinatorError = lastError
                }
            } else {
                lastCoordinatorError = nil
            }
        }

        if let error = status["error"] as? String {
            if error != lastHelperStatusError {
                appendLog("Peer service: \(error)")
                lastHelperStatusError = error
            }
        } else {
            lastHelperStatusError = nil
        }

        if let credential = status["credential"] as? [String: Any],
           let encoded = try? JSONSerialization.data(withJSONObject: credential, options: [.sortedKeys]),
           let secrets,
           encoded != secrets.credential
        {
            let updated = ActivePeerSecrets(
                signingPrivate: secrets.signingPrivate,
                noisePrivate: secrets.noisePrivate,
                credential: encoded
            )
            do {
                try VelaKeychain.save(updated)
                self.secrets = updated
                appendLog("Saved refreshed Coordinator credential to Keychain")
            } catch {
                appendLog("Could not save refreshed credential: \(error.localizedDescription)")
            }
        }
    }

    private func parseRegistrationText() {
        guard !registrationText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            registrationPreview = nil
            registrationError = nil
            return
        }
        do {
            registrationPreview = try RegistrationBundle(text: registrationText)
            registrationError = nil
        } catch {
            registrationPreview = nil
            registrationError = error.localizedDescription
        }
    }

    private func loadLocalState() {
        do {
            configJSON = try PeerFiles.loadConfig()
            secrets = try VelaKeychain.load()
            if let configJSON {
                guard savedCoordinator(from: configJSON) != nil else {
                    alertMessage = PeerAppError.invalidSavedPeerSettings.localizedDescription
                    return
                }
                guard let secrets, secrets.hasValidIdentity, !secrets.credential.isEmpty else {
                    alertMessage = PeerAppError.incompleteKeychainIdentity.localizedDescription
                    return
                }
            } else if let secrets {
                if !secrets.hasValidIdentity {
                    alertMessage = PeerAppError.incompleteKeychainIdentity.localizedDescription
                } else if !secrets.credential.isEmpty {
                    alertMessage = PeerAppError.peerSettingsMissing.localizedDescription
                }
            }
        } catch {
            alertMessage = "Could not load local Vela data: \(error.localizedDescription)"
        }
    }

    private func loadLogs() {
        guard let contents = try? String(contentsOf: PeerFiles.log, encoding: .utf8) else { return }
        logs = Array(contents.split(separator: "\n").suffix(200).map(String.init))
    }

    private func appendLog(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "\(timestamp)  \(message)"
        logs.append(line)
        if logs.count > 200 { logs.removeFirst(logs.count - 200) }
        PeerFiles.appendLog(line)
    }

    private func normalizedCoordinatorURL(_ value: String) -> String {
        guard var components = URLComponents(string: value) else { return value }
        components.scheme = components.scheme?.lowercased()
        components.host = components.host?.lowercased()
        if (components.scheme == "ws" && components.port == 80)
            || (components.scheme == "wss" && components.port == 443)
        {
            components.port = nil
        }
        var path = components.percentEncodedPath
        if path == "/" { path = "" }
        components.percentEncodedPath = path
        return components.string ?? value
    }

    private func savedCoordinator(from config: Data) -> SavedCoordinator? {
        guard let object = try? JSONSerialization.jsonObject(with: config) as? [String: Any],
              let server = object["server"] as? String,
              let url = URL(string: server),
              ["ws", "wss"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil,
              let encodedKey = object["server_key"] as? String,
              let publicKey = Data(base64Encoded: encodedKey),
              publicKey.count == 32
        else { return nil }
        return SavedCoordinator(url: server, publicKey: publicKey)
    }

    private var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    private func versionComponents(_ value: String) -> [Int]? {
        let trimmed = value.hasPrefix("v") ? String(value.dropFirst()) : value
        let pieces = trimmed.split(separator: ".", omittingEmptySubsequences: false)
        guard !pieces.isEmpty else { return nil }
        var result: [Int] = []
        for piece in pieces {
            guard let number = Int(piece), number >= 0 else { return nil }
            result.append(number)
        }
        return result
    }

    private func compareVersions(_ lhs: [Int], _ rhs: [Int]) -> Int {
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left < right ? -1 : 1 }
        }
        return 0
    }
}

private struct GitHubRelease: Decodable {
    let tagName: String
    let htmlURL: String

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case htmlURL = "html_url"
    }
}
