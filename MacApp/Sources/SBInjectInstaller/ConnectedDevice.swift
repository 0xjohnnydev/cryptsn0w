struct ConnectedDevice: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let model: String
    let systemVersion: String
    let transport: String

    var pickerTitle: String {
        name == model ? name : "\(name) — \(model)"
    }

    var detail: String {
        let version = systemVersion == "unknown" ? "iOS" : "iOS \(systemVersion)"
        return "\(version) • \(transport) • \(id)"
    }
}
