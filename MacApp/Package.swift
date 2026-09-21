// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "CryptSn0w",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CryptSn0w", targets: ["CryptSn0w"]),
    ],
    targets: [
        .executableTarget(
            name: "CryptSn0w",
            path: "Sources/SBInjectInstaller"
        ),
    ]
)
