// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BridgeheadApp",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "BridgeheadApp", targets: ["BridgeheadApp"]),
    ],
    targets: [
        .executableTarget(
            name: "BridgeheadApp",
            path: "Sources"
        ),
    ]
)
