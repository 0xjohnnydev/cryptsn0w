import CryptoKit
import Foundation
import Testing

@testable import OnDeviceCryptexCore

@Test func trustCacheMatchesCryptex1Layout() throws {
  let first = Data(repeating: 0xAA, count: 20)
  let second = Data(repeating: 0xBB, count: 20)
  let uuid = try #require(UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF"))

  let result = try CryptexPayloadBuilder.makeTrustCache(
    cdhashes: [second, first, first],
    uuid: uuid
  )

  #expect(
    result.hex == "30581604494d3450160467746364160463707478044401000000"
      + "00112233445566778899aabbccddeeff02000000" + String(repeating: "aa", count: 20) + "02c0"
      + String(repeating: "bb", count: 20) + "02c0"
  )
}

@Test func trustCacheRejectsAnInvalidCDHash() {
  #expect(throws: CryptexPayloadError.invalidCDHashLength(19)) {
    try CryptexPayloadBuilder.makeTrustCache(
      cdhashes: [Data(repeating: 0, count: 19)]
    )
  }
}

@Test func trustCacheIsAcceptedByCryptexctl() throws {
  let tool = "/System/Library/SecurityResearch/usr/bin/cryptexctl.research"
  guard FileManager.default.isExecutableFile(atPath: tool) else {
    return
  }

  let first = Data(repeating: 0xAA, count: 20)
  let second = Data(repeating: 0xBB, count: 20)
  let trustCache = try CryptexPayloadBuilder.makeTrustCache(
    cdhashes: [second, first],
    uuid: UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!
  )
  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(
    at: directory,
    withIntermediateDirectories: true
  )
  defer { try? FileManager.default.removeItem(at: directory) }

  let path = directory.appendingPathComponent("gtcd")
  try trustCache.write(to: path)

  let output = Pipe()
  let process = Process()
  process.executableURL = URL(fileURLWithPath: tool)
  process.arguments = ["dump-trust-cache", path.path]
  process.standardOutput = output
  process.standardError = output
  try process.run()
  process.waitUntilExit()

  let text = String(
    decoding: output.fileHandleForReading.readDataToEndOfFile(),
    as: UTF8.self
  )
  #expect(process.terminationStatus == 0)
  #expect(text.contains("00112233-4455-6677-8899-AABBCCDDEEFF"))
  #expect(text.contains("entry count = 2"))
  #expect(text.contains(String(repeating: "aa", count: 20)))
  #expect(text.contains(String(repeating: "bb", count: 20)))
}

@Test func infoUsesTheRequestedIdentity() throws {
  let data = try CryptexPayloadBuilder.makeInfo(
    identifier: "com.example.carrier",
    version: "1.2.3"
  )
  let info = try #require(
    PropertyListSerialization.propertyList(
      from: data,
      options: [],
      format: nil
    ) as? [String: String]
  )

  #expect(info["CFBundleIdentifier"] == "com.example.carrier")
  #expect(info["CFBundleVersion"] == "1.2.3")
  #expect(info["Version"] == "1.2.3")
}

@Test func manifestChangesOnlyMutablePayloadDigests() throws {
  let originalDmgDigest = Data(repeating: 0x11, count: 48)
  let originalVolumeDigest = Data(repeating: 0x22, count: 48)
  let carrier = try makeCarrierManifest(
    dmgDigest: originalDmgDigest,
    volumeDigest: originalVolumeDigest
  )
  let info = Data("new-info".utf8)
  let trustCache = Data("new-trust-cache".utf8)

  let result = try CryptexPayloadBuilder.updateManifest(
    carrier,
    info: info,
    trustCache: trustCache
  )
  let manifest = try manifestComponents(result)

  #expect(
    digest(manifest, "Cryptex1,CryptexInfoPlist") == Data(SHA384.hash(data: info))
  )
  #expect(
    digest(manifest, "Cryptex1,GenericTrustCache") == Data(SHA384.hash(data: trustCache))
  )
  #expect(digest(manifest, "Cryptex1,GenericDmg") == originalDmgDigest)
  #expect(digest(manifest, "Cryptex1,GenericVolume") == originalVolumeDigest)
}

private func makeCarrierManifest(
  dmgDigest: Data,
  volumeDigest: Data
) throws -> Data {
  func component(_ path: String, digest: Data) -> [String: Any] {
    [
      "Digest": digest,
      "Info": [
        "HashMethod": "sha2-384",
        "Path": path,
      ],
    ]
  }

  let root: [String: Any] = [
    "BuildIdentities": [
      [
        "Cryptex1,NonceDomain": 3,
        "Manifest": [
          "Cryptex1,CryptexInfoPlist": component(
            "Cryptex/default/ginf",
            digest: Data(repeating: 0x33, count: 48)
          ),
          "Cryptex1,GenericDmg": component(
            "Cryptex/default/gdmg",
            digest: dmgDigest
          ),
          "Cryptex1,GenericTrustCache": component(
            "Cryptex/default/gtcd",
            digest: Data(repeating: 0x44, count: 48)
          ),
          "Cryptex1,GenericVolume": component(
            "Cryptex/default/gtgv",
            digest: volumeDigest
          ),
        ],
      ]
    ]
  ]
  return try PropertyListSerialization.data(
    fromPropertyList: root,
    format: .xml,
    options: 0
  )
}

private func manifestComponents(_ data: Data) throws -> [String: Any] {
  let root = try #require(
    PropertyListSerialization.propertyList(
      from: data,
      options: [],
      format: nil
    ) as? [String: Any]
  )
  let identities = try #require(root["BuildIdentities"] as? [[String: Any]])
  return try #require(identities.first?["Manifest"] as? [String: Any])
}

private func digest(_ manifest: [String: Any], _ key: String) -> Data? {
  (manifest[key] as? [String: Any])?["Digest"] as? Data
}

extension Data {
  fileprivate var hex: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
