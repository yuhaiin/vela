import Foundation

@objc public protocol PeerHelperProtocol {
    func startPeer(_ request: Data, withReply reply: @escaping (Data?, String?) -> Void)
    func stopPeer(withReply reply: @escaping (String?) -> Void)
    func peerStatus(withReply reply: @escaping (Data) -> Void)
}
