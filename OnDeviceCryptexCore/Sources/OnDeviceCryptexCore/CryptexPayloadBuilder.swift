import CryptoKit
import Foundation

public enum CryptexPayloadError: Error, Equatable, LocalizedError {
  case emptyIdentifier
  case emptyVersion
  case invalidCDHashLength(Int)
  case tooManyCDHashes
  case invalidCarrierManifest

  public var errorDescription: String? {
    switch self {
    case .emptyIdentifier:
      "The Cryptex identifier is empty."
    case .emptyVersion:
      "The Cryptex version is empty."
    case .invalidCDHashLength(let length):
      "A CDHash is \(length) bytes. Each CDHash must be 20 bytes."
    case .tooManyCDHashes:
      "The trust cache has more entries than its format supports."
    case .invalidCarrierManifest:
      "The carrier BuildManifest does not contain one complete Cryptex1 identity."
    }
  }
}

public struct CryptexMutablePayloads: Sendable {
  public let info: Data
  public let trustCache: Data
  public let buildManifest: Data
}

/// Creates the small payloads that change when a fixed Cryptex image trusts
/// new code. The caller keeps the carrier's `gdmg` and `gtgv` files unchanged.
public enum CryptexPayloadBuilder {
  public static func make(
    carrierManifest: Data,
    identifier: String,
    version: String,
    cdhashes: [Data],
    trustCacheUUID: UUID = UUID()
  ) throws -> CryptexMutablePayloads {
    let info = try makeInfo(identifier: identifier, version: version)
    let trustCache = try makeTrustCache(
      cdhashes: cdhashes,
      uuid: trustCacheUUID
    )
    let buildManifest = try updateManifest(
      carrierManifest,
      info: info,
      trustCache: trustCache
    )
    return CryptexMutablePayloads(
      info: info,
      trustCache: trustCache,
      buildManifest: buildManifest
    )
  }

  public static func makeInfo(
    identifier: String,
    version: String
  ) throws -> Data {
    guard !identifier.isEmpty else {
      throw CryptexPayloadError.emptyIdentifier
    }
    guard !version.isEmpty else {
      throw CryptexPayloadError.emptyVersion
    }

    return try PropertyListSerialization.data(
      fromPropertyList: [
        "CFBundleIdentifier": identifier,
        "CFBundleVersion": version,
        "Name": identifier,
        "Publisher": "cryptexctl",
        "Version": version,
      ],
      format: .xml,
      options: 0
    )
  }

  public static func makeTrustCache(
    cdhashes: [Data],
    uuid: UUID = UUID()
  ) throws -> Data {
    for cdhash in cdhashes where cdhash.count != 20 {
      throw CryptexPayloadError.invalidCDHashLength(cdhash.count)
    }

    let entries = Array(Set(cdhashes)).sorted {
      $0.lexicographicallyPrecedes($1)
    }
    guard let count = UInt32(exactly: entries.count) else {
      throw CryptexPayloadError.tooManyCDHashes
    }

    var payload = Data()
    payload.appendLittleEndian(UInt32(1))

    var uuidBytes = uuid.uuid
    withUnsafeBytes(of: &uuidBytes) {
      payload.append(contentsOf: $0)
    }

    payload.appendLittleEndian(count)
    for cdhash in entries {
      payload.append(cdhash)
      payload.append(0x02)  // CS_HASHTYPE_SHA256_TRUNCATED
      payload.append(0xC0)  // CS_TC_BEFORE_REM | CS_TC_AFTER_REM
    }

    var image4 = Data()
    image4.appendDER(tag: 0x16, content: Data("IM4P".utf8))
    image4.appendDER(tag: 0x16, content: Data("gtcd".utf8))
    image4.appendDER(tag: 0x16, content: Data("cptx".utf8))
    image4.appendDER(tag: 0x04, content: payload)

    var result = Data()
    result.appendDER(tag: 0x30, content: image4)
    return result
  }

  public static func updateManifest(
    _ carrierManifest: Data,
    info: Data,
    trustCache: Data
  ) throws -> Data {
    guard
      var root = try PropertyListSerialization.propertyList(
        from: carrierManifest,
        options: [],
        format: nil
      ) as? [String: Any],
      var identities = root["BuildIdentities"] as? [[String: Any]],
      identities.count == 1,
      var manifest = identities[0]["Manifest"] as? [String: Any],
      manifest["Cryptex1,GenericDmg"] is [String: Any],
      manifest["Cryptex1,GenericVolume"] is [String: Any]
    else {
      throw CryptexPayloadError.invalidCarrierManifest
    }

    try replaceDigest(
      in: &manifest,
      key: "Cryptex1,CryptexInfoPlist",
      payload: info
    )
    try replaceDigest(
      in: &manifest,
      key: "Cryptex1,GenericTrustCache",
      payload: trustCache
    )

    identities[0]["Manifest"] = manifest
    root["BuildIdentities"] = identities
    return try PropertyListSerialization.data(
      fromPropertyList: root,
      format: .xml,
      options: 0
    )
  }

  private static func replaceDigest(
    in manifest: inout [String: Any],
    key: String,
    payload: Data
  ) throws {
    guard
      var component = manifest[key] as? [String: Any],
      component["Digest"] is Data,
      let componentInfo = component["Info"] as? [String: Any],
      componentInfo["HashMethod"] as? String == "sha2-384",
      componentInfo["Path"] is String
    else {
      throw CryptexPayloadError.invalidCarrierManifest
    }

    component["Digest"] = Data(SHA384.hash(data: payload))
    manifest[key] = component
  }
}

extension Data {
  fileprivate mutating func appendLittleEndian(_ value: UInt32) {
    var littleEndian = value.littleEndian
    Swift.withUnsafeBytes(of: &littleEndian) {
      append(contentsOf: $0)
    }
  }

  fileprivate mutating func appendDER(tag: UInt8, content: Data) {
    append(tag)
    append(contentsOf: Self.derLength(content.count))
    append(content)
  }

  fileprivate static func derLength(_ length: Int) -> [UInt8] {
    if length < 0x80 {
      return [UInt8(length)]
    }

    var value = length
    var bytes: [UInt8] = []
    while value > 0 {
      bytes.insert(UInt8(value & 0xFF), at: 0)
      value >>= 8
    }
    return [0x80 | UInt8(bytes.count)] + bytes
  }
}
