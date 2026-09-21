// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "OnDeviceCryptexCore",
  platforms: [
    .iOS(.v17),
    .macOS(.v14),
  ],
  products: [
    .library(
      name: "OnDeviceCryptexCore",
      targets: ["OnDeviceCryptexCore"]
    )
  ],
  targets: [
    .target(name: "OnDeviceCryptexCore"),
    .testTarget(
      name: "OnDeviceCryptexCoreTests",
      dependencies: ["OnDeviceCryptexCore"]
    ),
  ]
)
