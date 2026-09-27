// swift-tools-version: 5.9
import PackageDescription
import Foundation

let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let rustLibraryDirectory = "\(packageDirectory)/Rust"
let rustLinkerSettings: [LinkerSetting] = [
    .unsafeFlags(["-L\(rustLibraryDirectory)", "-lvela_peer_service", "-lc++"]),
    .linkedFramework("CoreFoundation"),
    .linkedFramework("Security"),
]

let package = Package(
    name: "VelaPeerMac",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "VelaPeer", targets: ["VelaPeerApp"]),
        .executable(name: "VelaPeerHelper", targets: ["VelaPeerHelper"]),
    ],
    targets: [
        .target(
            name: "VelaPeerFFI",
            path: "FFI",
            publicHeadersPath: "include"
        ),
        .target(
            name: "VelaPeerShared",
            path: "Shared"
        ),
        .executableTarget(
            name: "VelaPeerApp",
            dependencies: ["VelaPeerFFI", "VelaPeerShared"],
            path: "App",
            linkerSettings: rustLinkerSettings + [
                .linkedFramework("AVFoundation"),
                .linkedFramework("ServiceManagement"),
                .linkedFramework("SwiftUI"),
                .linkedFramework("Vision"),
            ]
        ),
        .executableTarget(
            name: "VelaPeerHelper",
            dependencies: ["VelaPeerFFI", "VelaPeerShared"],
            path: "Helper",
            linkerSettings: rustLinkerSettings + [
                .linkedFramework("ServiceManagement"),
            ]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
