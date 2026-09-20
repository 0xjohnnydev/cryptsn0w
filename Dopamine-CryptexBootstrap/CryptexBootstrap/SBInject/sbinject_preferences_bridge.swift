import Foundation

private func child(_ value: Any, named name: String) -> Any? {
    for entry in Mirror(reflecting: value).children where entry.label == name {
        return entry.value
    }
    return nil
}

private func firstChild(_ value: Any) -> Any? {
    return Mirror(reflecting: value).children.first?.value
}

private func lastChild(_ value: Any) -> Any? {
    var result: Any?
    for entry in Mirror(reflecting: value).children {
        result = entry.value
    }
    return result
}

private func metadata(of value: Any) -> UnsafeRawPointer {
    return unsafeBitCast(Swift.type(of: value), to: UnsafeRawPointer.self)
}

private protocol PL27AnyDictionary {
    mutating func insertAny(key: Any, value: Any) -> Bool
    func storageWord() -> UInt
}

extension Dictionary: PL27AnyDictionary {
    fileprivate mutating func insertAny(key: Any, value: Any) -> Bool {
        guard let key = key as? Key, let value = value as? Value else {
            return false
        }
        self[key] = value
        return true
    }

    fileprivate func storageWord() -> UInt {
        var copy = self
        return withUnsafeBytes(of: &copy) { bytes in
            bytes.load(as: UInt.self)
        }
    }
}

@_silgen_name("PL27ReplaceDictionaryStorages")
private func PL27ReplaceDictionaryStorages(
    _ firstField: UnsafeMutableRawPointer,
    _ firstStorageWord: UInt,
    _ secondField: UnsafeMutableRawPointer,
    _ secondStorageWord: UInt
) -> Bool

// Output order: snapshot, section, item, section identifier, item identifier,
// item view type, label model.
@_cdecl("PL27DiscoverMetadata")
public func PL27DiscoverMetadata(
    _ objectPointer: UnsafeRawPointer?,
    _ output: UnsafeMutablePointer<UnsafeRawPointer?>?,
    _ capacity: Int
) -> Int32 {
    guard let objectPointer, let output, capacity >= 7 else { return 0 }
    let object = Unmanaged<AnyObject>.fromOpaque(objectPointer).takeUnretainedValue()
    guard
        let cached = child(object, named: "_cachedSnapshot"),
        let snapshot = firstChild(cached),
        let sections = child(snapshot, named: "sections"),
        let section = firstChild(sections),
        let sectionIdentifier = child(section, named: "id"),
        let items = child(section, named: "items"),
        let item = firstChild(items),
        let itemIdentifier = child(item, named: "id"),
        let viewType = child(item, named: "type")
    else { return 0 }

    var labelModel: Any?
    for sectionValue in Mirror(reflecting: sections).children {
        guard let sectionItems = child(sectionValue.value, named: "items") else { continue }
        for itemValue in Mirror(reflecting: sectionItems).children {
            guard let candidateType = child(itemValue.value, named: "type") else { continue }
            let typeMirror = Mirror(reflecting: candidateType)
            guard let labelTuple = typeMirror.children.first(where: { $0.label == "label" })?.value,
                  let candidateModel = child(labelTuple, named: "model") else { continue }
            labelModel = candidateModel
            break
        }
        if labelModel != nil { break }
    }
    guard let labelModel else { return 0 }

    let values: [Any] = [
        snapshot, section, item, sectionIdentifier, itemIdentifier, viewType,
        labelModel,
    ]
    for (index, value) in values.enumerated() {
        output[index] = metadata(of: value)
    }
    return 7
}

@_cdecl("PL27UpdateLookups")
public func PL27UpdateLookups(
    _ objectPointer: UnsafeRawPointer?,
    _ snapshotPointer: UnsafeMutableRawPointer?,
    _ sectionLookupOffset: Int32,
    _ itemLookupOffset: Int32
) -> Bool {
    guard
        let objectPointer,
        let snapshotPointer,
        sectionLookupOffset >= 0,
        itemLookupOffset >= 0
    else { return false }

    let object = Unmanaged<AnyObject>.fromOpaque(objectPointer).takeUnretainedValue()
    guard
        let cached = child(object, named: "_cachedSnapshot"),
        let snapshot = firstChild(cached),
        let sections = child(snapshot, named: "sections"),
        let lastSection = lastChild(sections),
        let sectionKey = child(lastSection, named: "id"),
        let items = child(lastSection, named: "items"),
        let sectionLookupValue = child(snapshot, named: "sectionIdentifierLookup"),
        let itemLookupValue = child(snapshot, named: "itemIdentifierLookup")
    else { return false }

    guard var sectionLookup = sectionLookupValue as? any PL27AnyDictionary,
          var itemLookup = itemLookupValue as? any PL27AnyDictionary,
          sectionLookup.insertAny(key: sectionKey, value: lastSection)
    else { return false }
    for itemEntry in Mirror(reflecting: items).children {
        guard let itemKey = child(itemEntry.value, named: "id"),
              itemLookup.insertAny(key: itemKey, value: itemEntry.value)
        else { return false }
    }

    let sectionStorage = sectionLookup.storageWord()
    let itemStorage = itemLookup.storageWord()
    guard sectionStorage != 0, itemStorage != 0 else { return false }

    // Install both atomically while the existential copies own their storage.
    return PL27ReplaceDictionaryStorages(
        snapshotPointer.advanced(by: Int(sectionLookupOffset)),
        sectionStorage,
        snapshotPointer.advanced(by: Int(itemLookupOffset)),
        itemStorage
    )
}
