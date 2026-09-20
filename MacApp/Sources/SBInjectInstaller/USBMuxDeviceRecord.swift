struct USBMuxDeviceRecord: Decodable, Sendable {
    let buildVersion: String?
    let connectionType: String?
    let deviceClass: String?
    let deviceName: String?
    let identifier: String?
    let productType: String?
    let productVersion: String?
    let uniqueDeviceID: String?

    enum CodingKeys: String, CodingKey {
        case buildVersion = "BuildVersion"
        case connectionType = "ConnectionType"
        case deviceClass = "DeviceClass"
        case deviceName = "DeviceName"
        case identifier = "Identifier"
        case productType = "ProductType"
        case productVersion = "ProductVersion"
        case uniqueDeviceID = "UniqueDeviceID"
    }
}
