import Foundation

enum InstallerFailure: LocalizedError {
    case exitStatus(Int32)

    var errorDescription: String? {
        switch self {
        case .exitStatus(let status):
            "The installer exited with status \(status). Review the log for the exact failure."
        }
    }
}
