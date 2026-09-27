import Darwin
import Foundation
import VelaPeerFFI
import VelaPeerShared

private final class PeerHelperService: NSObject, PeerHelperProtocol {
    private let queue = DispatchQueue(label: "com.vela.peer.helper.service")
    private var serviceHandle: UnsafeMutableRawPointer?
    private var activeClient: NSXPCConnection?

    func accept(_ connection: NSXPCConnection) -> Bool {
        queue.sync {
            guard activeClient == nil else { return false }
            activeClient = connection
            return true
        }
    }

    func clientDisconnected(_ connection: NSXPCConnection) {
        queue.async {
            guard self.activeClient === connection else { return }
            self.activeClient = nil
            if let error = self.stopService() {
                NSLog("Vela peer shutdown failed after app disconnect: %@", error)
            }
            // Exit once idle so a later app launch loads the helper executable
            // from the current Vela.app bundle after a manual app update.
            self.queue.asyncAfter(deadline: .now() + .seconds(1)) {
                guard self.activeClient == nil else { return }
                exit(EXIT_SUCCESS)
            }
        }
    }

    func terminate() {
        queue.async {
            self.activeClient?.invalidate()
            self.activeClient = nil
            if let error = self.stopService() {
                NSLog("Vela peer shutdown failed during helper termination: %@", error)
            }
            exit(EXIT_SUCCESS)
        }
    }

    func startPeer(_ request: Data, withReply reply: @escaping (Data?, String?) -> Void) {
        queue.async {
            if let existing = self.serviceHandle {
                let status = self.statusData(existing)
                let running = (try? JSONSerialization.jsonObject(with: status)) as? [String: Any]
                if running?["running"] as? Bool == true {
                    reply(status, nil)
                    return
                }
                _ = self.stopService()
            }
            var error: UnsafeMutablePointer<CChar>?
            let handle = request.withUnsafeBytes { bytes in
                vela_peer_service_start(
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    bytes.count,
                    &error
                )
            }
            if let error {
                let message = String(cString: error)
                vela_string_free(error)
                reply(nil, message)
                return
            }
            guard let handle else {
                reply(nil, "Rust peer service failed to start.")
                return
            }
            self.serviceHandle = handle
            reply(self.statusData(handle), nil)
        }
    }

    func stopPeer(withReply reply: @escaping (String?) -> Void) {
        queue.async {
            reply(self.stopService())
        }
    }

    func peerStatus(withReply reply: @escaping (Data) -> Void) {
        queue.async {
            guard let handle = self.serviceHandle else {
                reply(Data("{\"running\":false}".utf8))
                return
            }
            reply(self.statusData(handle))
        }
    }

    private func statusData(_ handle: UnsafeMutableRawPointer) -> Data {
        guard let value = vela_peer_service_status(handle) else {
            return Data("{\"running\":false}".utf8)
        }
        defer { vela_string_free(value) }
        return Data(String(cString: value).utf8)
    }

    private func stopService() -> String? {
        guard let handle = serviceHandle else { return nil }
        serviceHandle = nil
        guard let error = vela_peer_service_stop(handle) else { return nil }
        defer { vela_string_free(error) }
        return String(cString: error)
    }
}

private final class PeerHelperListener: NSObject, NSXPCListenerDelegate {
    private let service = PeerHelperService()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard service.accept(connection) else { return false }
        connection.setCodeSigningRequirement(PeerSigningIdentity.appRequirement)
        connection.exportedInterface = NSXPCInterface(with: PeerHelperProtocol.self)
        connection.exportedObject = service
        connection.invalidationHandler = { [weak self, weak connection] in
            guard let connection else { return }
            self?.service.clientDisconnected(connection)
        }
        connection.interruptionHandler = { [weak self, weak connection] in
            guard let connection else { return }
            self?.service.clientDisconnected(connection)
        }
        connection.resume()
        return true
    }
}

private let listenerDelegate = PeerHelperListener()
private let listener = NSXPCListener(machServiceName: "com.vela.peer.helper")
_ = signal(SIGTERM, SIG_IGN)
private let terminationSignal = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
terminationSignal.setEventHandler { listenerDelegate.terminate() }
terminationSignal.resume()
listener.delegate = listenerDelegate
listener.resume()
RunLoop.current.run()
