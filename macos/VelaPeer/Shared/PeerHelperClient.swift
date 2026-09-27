import Foundation
import VelaPeerShared

private final class PeerHelperCompletion<Value> {
    private let lock = NSLock()
    private let continuation: CheckedContinuation<Value, Error>
    private var completed = false

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<Value, Error>) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        lock.unlock()
        continuation.resume(with: result)
    }
}

public enum PeerHelperError: LocalizedError {
    case unavailable(String)
    case emptyResponse

    public var errorDescription: String? {
        switch self {
        case .unavailable(let message): "The Vela helper is unavailable: \(message)"
        case .emptyResponse: "The Vela helper returned an empty response."
        }
    }
}

@MainActor
public final class PeerHelperClient {
    private let connection: NSXPCConnection
    public var onDisconnect: (() -> Void)?

    public init(onDisconnect: (() -> Void)? = nil) {
        self.onDisconnect = onDisconnect
        connection = NSXPCConnection(
            machServiceName: "com.vela.peer.helper",
            options: .privileged
        )
        connection.remoteObjectInterface = NSXPCInterface(with: PeerHelperProtocol.self)
        connection.setCodeSigningRequirement(PeerSigningIdentity.helperRequirement)
        connection.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.onDisconnect?() }
        }
        connection.interruptionHandler = { [weak self] in
            Task { @MainActor in self?.onDisconnect?() }
        }
        connection.resume()
    }

    public func startPeer(_ request: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            let completion = PeerHelperCompletion(continuation)
            proxy(completion).startPeer(request) { data, error in
                if let error {
                    completion.finish(.failure(PeerHelperError.unavailable(error)))
                } else if let data {
                    completion.finish(.success(data))
                } else {
                    completion.finish(.failure(PeerHelperError.emptyResponse))
                }
            }
        }
    }

    public func stopPeer() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let completion = PeerHelperCompletion(continuation)
            proxy(completion).stopPeer { error in
                if let error {
                    completion.finish(.failure(PeerHelperError.unavailable(error)))
                } else {
                    completion.finish(.success(()))
                }
            }
        }
    }

    public func peerStatus() async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            let completion = PeerHelperCompletion(continuation)
            proxy(completion).peerStatus { completion.finish(.success($0)) }
        }
    }

    public func invalidate() {
        connection.invalidate()
    }

    private func proxy<Value>(_ completion: PeerHelperCompletion<Value>) -> PeerHelperProtocol {
        connection.remoteObjectProxyWithErrorHandler { error in
            NSLog("Vela helper XPC error: %@", error.localizedDescription)
            completion.finish(.failure(PeerHelperError.unavailable(error.localizedDescription)))
        } as! PeerHelperProtocol
    }
}
