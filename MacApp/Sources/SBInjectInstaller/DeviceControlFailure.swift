import Foundation

enum DeviceControlFailure: LocalizedError {
    case notConnected
    case commandFailed(String)
    case unreadableResponse(String)
    case unsupportedDrop
    case archiveFailed(String)
    case noBundleInArchive

    var errorDescription: String? {
        switch self {
        case .notConnected:
            "The device is no longer reachable over the SSH forward."
        case let .commandFailed(detail):
            detail
        case let .unreadableResponse(detail):
            "customctl returned something unreadable: \(detail)"
        case .unsupportedDrop:
            "Drop an .ipa archive or an .app bundle."
        case let .archiveFailed(detail):
            "The archive could not be expanded. \(detail)"
        case .noBundleInArchive:
            "That .ipa does not contain a Payload/<name>.app bundle."
        }
    }
}
