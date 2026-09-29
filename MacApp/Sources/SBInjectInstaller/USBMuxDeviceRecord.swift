struct USBMuxDeviceRecord: Decodable, Sendable {
    let connectionType: String?
    let deviceName: String?
    let identifier: String?
    let productType: String?
    let productVersion: String?
    let uniqueDeviceID: String?

    enum CodingKeys: String, CodingKey {
        case connectionType = "ConnectionType"
        case deviceName = "DeviceName"
        case identifier = "Identifier"
        case productType = "ProductType"
        case productVersion = "ProductVersion"
        case uniqueDeviceID = "UniqueDeviceID"
    }
}
