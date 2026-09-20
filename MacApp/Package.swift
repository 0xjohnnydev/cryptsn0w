// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "SBInjectInstaller",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SBInjectInstaller", targets: ["SBInjectInstaller"]),
    ],
    targets: [
        .executableTarget(
            name: "SBInjectInstaller",
            path: "Sources/SBInjectInstaller"
        ),
    ]
)
