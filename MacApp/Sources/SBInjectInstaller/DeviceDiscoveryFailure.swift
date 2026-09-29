import Foundation

enum DeviceDiscoveryFailure: LocalizedError {
    case missingTool
    case commandFailed(String)
    case invalidResponse
    case noDevices

    var errorDescription: String? {
        switch self {
        case .missingTool:
            "pymobiledevice3 is unavailable. Run ‘make python’ in the repository, then refresh devices."
        case .commandFailed(let detail):
            "The connected-device query failed. \(detail)"
        case .invalidResponse:
            "The connected-device query returned an unreadable response."
        case .noDevices:
            "No paired device was found. Connect and unlock the iPhone, trust this Mac, then refresh."
        }
    }
}
