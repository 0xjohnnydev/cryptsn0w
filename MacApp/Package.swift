// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "CryptexSn0w",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CryptexSn0w", targets: ["CryptexSn0w"]),
    ],
    targets: [
        .executableTarget(
            name: "CryptexSn0w",
            path: "Sources/SBInjectInstaller"
        ),
    ]
)
