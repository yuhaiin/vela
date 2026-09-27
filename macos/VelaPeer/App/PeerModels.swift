import CryptoKit
import Foundation
import Security
import VelaPeerFFI

func coordinatorKeyFingerprint(_ key: Data) -> String {
    let octets = SHA256.hash(data: key).map { String(format: "%02X", $0) }
    let groups = stride(from: 0, to: octets.count, by: 4).map { start in
        octets[start..<min(start + 4, octets.count)].joined()
    }
    return "SHA-256 " + groups.joined(separator: " ")
}

struct RegistrationBundle: Decodable {
    let version: Int
    let coordinator: Coordinator
    let invite: String

    struct Coordinator: Decodable {
        let url: String
        let publicKey: String

        enum CodingKeys: String, CodingKey {
            case url
            case publicKey = "public_key"
        }
    }

    init(text: String) throws {
        let data = Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        self = try JSONDecoder().decode(Self.self, from: data)
        guard version == 1 else { throw PeerAppError.unsupportedBundleVersion(version) }
        guard let url = URL(string: coordinator.url),
              ["ws", "wss"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil
        else {
            throw PeerAppError.invalidRegistrationBundle("Coordinator URL must use ws:// or wss://")
        }
        guard let key = Data(base64Encoded: coordinator.publicKey), key.count == 32 else {
            throw PeerAppError.invalidRegistrationBundle("Coordinator public key must be 32 bytes")
        }
        guard !invite.isEmpty else {
            throw PeerAppError.invalidRegistrationBundle("Registration invite is empty")
        }
    }

    var fingerprint: String {
        let key = Data(base64Encoded: coordinator.publicKey) ?? Data()
        return coordinatorKeyFingerprint(key)
    }
}

struct ActivePeerSecrets: Codable {
    let signingPrivate: Data
    let noisePrivate: Data
    var credential: Data

    var hasValidIdentity: Bool {
        signingPrivate.count == 32 && noisePrivate.count == 32
    }

    var identityMaterial: Data {
        var material = signingPrivate
        material.append(noisePrivate)
        return material
    }
}

struct VelaAppSettings: Codable {
    var launchAtLogin: Bool
    var helperSigningCertificate: String?

    private enum CodingKeys: String, CodingKey {
        case launchAtLogin
        case helperSigningCertificate
    }

    init(launchAtLogin: Bool = false, helperSigningCertificate: String? = nil) {
        self.launchAtLogin = launchAtLogin
        self.helperSigningCertificate = helperSigningCertificate
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        launchAtLogin = try container.decodeIfPresent(Bool.self, forKey: .launchAtLogin) ?? false
        helperSigningCertificate = try container.decodeIfPresent(String.self, forKey: .helperSigningCertificate)
    }
}

enum PeerAppError: LocalizedError {
    case invalidRegistrationBundle(String)
    case unsupportedBundleVersion(Int)
    case noRegistration
    case incompleteKeychainIdentity
    case peerSettingsMissing
    case invalidSavedPeerSettings
    case helperApprovalRequired
    case loginItemApprovalRequired
    case loginItemUnavailable(String)
    case helperUnavailable(String)
    case keychain(OSStatus)
    case rust(String)

    var errorDescription: String? {
        switch self {
        case .invalidRegistrationBundle(let message): message
        case .unsupportedBundleVersion(let version): "Registration bundle version \(version) is not supported."
        case .noRegistration: "Register this Mac before starting the peer."
        case .incompleteKeychainIdentity: "The Vela identity in Keychain is incomplete. Use Delete device data to reset local state."
        case .peerSettingsMissing: "Keychain still contains a registration credential, but the peer settings are missing. Restore the settings or delete local device data before registering again."
        case .invalidSavedPeerSettings: "Saved peer settings are invalid. Delete local device data and register again so Vela can confirm any Coordinator change."
        case .helperApprovalRequired: "Approve Vela Peer Helper in System Settings > General > Login Items, then try again."
        case .loginItemApprovalRequired: "Allow Vela to open at login in System Settings > General > Login Items."
        case .loginItemUnavailable(let message): "The Vela login item is unavailable: \(message)"
        case .helperUnavailable(let message): "The Vela helper is unavailable: \(message)"
        case .keychain(let status): "Keychain operation failed (\(status))."
        case .rust(let message): message
        }
    }
}

struct SavedCoordinator {
    let url: String
    let publicKey: Data
}

enum VelaKeychain {
    private static let service = "com.vela.peer"
    private static let account = "active-peer-secrets"

    static func load() throws -> ActivePeerSecrets? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw PeerAppError.keychain(status)
        }
        return try JSONDecoder().decode(ActivePeerSecrets.self, from: data)
    }

    static func save(_ secrets: ActivePeerSecrets) throws {
        let data = try JSONEncoder().encode(secrets)
        let status = SecItemUpdate(baseQuery as CFDictionary, [
            kSecValueData as String: data,
        ] as CFDictionary)
        if status == errSecItemNotFound {
            var query = baseQuery
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw PeerAppError.keychain(addStatus) }
        } else if status != errSecSuccess {
            throw PeerAppError.keychain(status)
        }
    }

    static func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PeerAppError.keychain(status)
        }
    }

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

enum PeerFiles {
    private static let maximumLogBytes = 512 * 1024
    private static let retainedLogLines = 199

    static var applicationSupportDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Vela", isDirectory: true)
    }

    static var directory: URL {
        applicationSupportDirectory.appendingPathComponent("peer", isDirectory: true)
    }

    static var settings: URL { applicationSupportDirectory.appendingPathComponent("settings.json") }
    static var config: URL { directory.appendingPathComponent("config.json") }
    static var log: URL { directory.appendingPathComponent("logs/peer.log") }

    static func loadSettings() throws -> VelaAppSettings {
        guard FileManager.default.fileExists(atPath: settings.path) else { return VelaAppSettings() }
        return try JSONDecoder().decode(VelaAppSettings.self, from: Data(contentsOf: settings))
    }

    static func saveSettings(_ settings: VelaAppSettings) throws {
        try FileManager.default.createDirectory(at: applicationSupportDirectory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(settings)
        try data.write(to: self.settings, options: .atomic)
    }

    static func saveConfig(_ data: Data) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: config, options: .atomic)
    }

    static func loadConfig() throws -> Data? {
        guard FileManager.default.fileExists(atPath: config.path) else { return nil }
        return try Data(contentsOf: config)
    }

    static func removeLocalData() throws {
        try VelaKeychain.delete()
        if FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.removeItem(at: directory)
        }
    }

    static func appendLog(_ line: String) {
        do {
            let logDirectory = log.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
            let data = Data((line + "\n").utf8)
            if FileManager.default.fileExists(atPath: log.path) {
                let attributes = try FileManager.default.attributesOfItem(atPath: log.path)
                let existingSize = (attributes[.size] as? NSNumber)?.intValue ?? 0
                if existingSize + data.count > maximumLogBytes {
                    let existing = try String(contentsOf: log, encoding: .utf8)
                    let retained = existing
                        .split(separator: "\n")
                        .suffix(retainedLogLines)
                        .joined(separator: "\n")
                    let contents = retained.isEmpty ? line + "\n" : retained + "\n" + line + "\n"
                    try Data(contents.utf8).write(to: log, options: .atomic)
                    return
                }
                let handle = try FileHandle(forWritingTo: log)
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
                try handle.close()
            } else {
                try data.write(to: log, options: .atomic)
            }
        } catch {
            NSLog("Vela log write failed: %@", error.localizedDescription)
        }
    }
}

enum RustBridge {
    struct RegistrationResult {
        let config: Data
        let credential: Data
    }

    struct GeneratedIdentity: Decodable {
        let signingPrivate: Data
        let noisePrivate: Data

        enum CodingKeys: String, CodingKey {
            case signingPrivate = "signing_private"
            case noisePrivate = "noise_private"
        }
    }

    static func generateIdentity() throws -> GeneratedIdentity {
        guard let output = vela_identity_generate() else {
            throw PeerAppError.rust("Could not generate a Vela identity.")
        }
        defer { vela_string_free(output) }
        return try JSONDecoder().decode(GeneratedIdentity.self, from: Data(String(cString: output).utf8))
    }

    static func createConfig(server: String, publicKey: String) throws -> Data {
        let serverData = Data(server.utf8)
        let keyData = Data(publicKey.utf8)
        var error: UnsafeMutablePointer<CChar>?
        let output = serverData.withUnsafeBytes { serverBytes in
            keyData.withUnsafeBytes { keyBytes in
                vela_peer_config_create(
                    serverBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    serverBytes.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    keyBytes.count,
                    &error
                )
            }
        }
        if let error { throw takeRustError(error) }
        guard let output else { throw PeerAppError.rust("Could not build Coordinator settings.") }
        defer { vela_string_free(output) }
        return Data(String(cString: output).utf8)
    }

    static func register(
        config: Data,
        identity: Data,
        invite: String
    ) throws -> RegistrationResult {
        let inviteData = Data(invite.utf8)
        var error: UnsafeMutablePointer<CChar>?
        let output = config.withUnsafeBytes { configBytes in
            identity.withUnsafeBytes { identityBytes in
                inviteData.withUnsafeBytes { inviteBytes in
                    vela_peer_register(
                        configBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        configBytes.count,
                        identityBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        identityBytes.count,
                        inviteBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        inviteBytes.count,
                        0,
                        &error
                    )
                }
            }
        }
        if let error { throw takeRustError(error) }
        guard let output else { throw PeerAppError.rust("Coordinator registration failed.") }
        defer { vela_string_free(output) }
        guard let object = try JSONSerialization.jsonObject(with: Data(String(cString: output).utf8)) as? [String: Any],
              let configObject = object["config"],
              let credentialObject = object["credential"]
        else {
            throw PeerAppError.rust("Vela returned an invalid registration response.")
        }
        return RegistrationResult(
            config: try JSONSerialization.data(withJSONObject: configObject, options: [.sortedKeys]),
            credential: try JSONSerialization.data(withJSONObject: credentialObject, options: [.sortedKeys])
        )
    }

    private static func takeRustError(_ pointer: UnsafeMutablePointer<CChar>) -> PeerAppError {
        let message = String(cString: pointer)
        vela_string_free(pointer)
        return .rust(message)
    }
}
