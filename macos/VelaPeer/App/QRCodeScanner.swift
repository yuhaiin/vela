import AVFoundation
import SwiftUI

@MainActor
private final class QRScannerModel: NSObject, ObservableObject, AVCaptureMetadataOutputObjectsDelegate {
    @Published var message = "Preparing camera…"
    let session = AVCaptureSession()
    private let onCode: (String) -> Void
    private let sessionQueue = DispatchQueue(label: "com.vela.peer.camera")
    private var configured = false

    init(onCode: @escaping (String) -> Void) {
        self.onCode = onCode
    }

    func start() async {
        let authorized: Bool
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            authorized = true
        case .notDetermined:
            authorized = await withCheckedContinuation { continuation in
                AVCaptureDevice.requestAccess(for: .video) { continuation.resume(returning: $0) }
            }
        default:
            authorized = false
        }
        guard authorized else {
            message = "Camera access is unavailable. Allow Vela in System Settings > Privacy & Security > Camera, or paste the registration bundle."
            return
        }
        guard !configured else {
            startSession()
            return
        }

        do {
            guard let device = AVCaptureDevice.default(for: .video) else {
                message = "No camera is available."
                return
            }
            let input = try AVCaptureDeviceInput(device: device)
            let output = AVCaptureMetadataOutput()
            session.beginConfiguration()
            session.sessionPreset = .high
            guard session.canAddInput(input), session.canAddOutput(output) else {
                session.commitConfiguration()
                message = "Vela could not configure the camera."
                return
            }
            session.addInput(input)
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            guard output.availableMetadataObjectTypes.contains(.qr) else {
                session.commitConfiguration()
                message = "This camera does not support QR scanning."
                return
            }
            output.metadataObjectTypes = [.qr]
            session.commitConfiguration()
            configured = true
            message = "Hold the Coordinator QR code in front of the camera."
            startSession()
        } catch {
            message = "Could not start the camera: \(error.localizedDescription)"
        }
    }

    func stop() {
        sessionQueue.async { [session] in
            if session.isRunning { session.stopRunning() }
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let code = metadataObjects
            .compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue })
            .first
        else { return }
        stop()
        onCode(code)
    }

    private func startSession() {
        sessionQueue.async { [session] in
            if !session.isRunning { session.startRunning() }
        }
    }
}

struct QRScannerSheet: View {
    let onCode: (String) -> Void
    @StateObject private var scanner: QRScannerModel
    @Environment(\.dismiss) private var dismiss

    init(onCode: @escaping (String) -> Void) {
        self.onCode = onCode
        _scanner = StateObject(wrappedValue: QRScannerModel(onCode: onCode))
    }

    var body: some View {
        VStack(spacing: 14) {
            CapturePreview(session: scanner.session)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(.quaternary))
            Text(scanner.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
        .padding(18)
        .task { await scanner.start() }
        .onDisappear { scanner.stop() }
    }
}

private struct CapturePreview: NSViewRepresentable {
    let session: AVCaptureSession

    func makeNSView(context: Context) -> CameraPreviewView {
        let view = CameraPreviewView()
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer = layer
        view.wantsLayer = true
        view.previewLayer = layer
        return view
    }

    func updateNSView(_ view: CameraPreviewView, context: Context) {
        view.previewLayer?.session = session
    }
}

private final class CameraPreviewView: NSView {
    var previewLayer: AVCaptureVideoPreviewLayer?

    override func layout() {
        super.layout()
        previewLayer?.frame = bounds
    }
}
