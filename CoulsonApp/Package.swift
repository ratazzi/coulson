// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CoulsonApp",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "CoulsonApp", targets: ["CoulsonApp"]),
    ],
    targets: [
        .executableTarget(
            name: "CoulsonApp",
            path: "Sources"
        ),
    ]
)
