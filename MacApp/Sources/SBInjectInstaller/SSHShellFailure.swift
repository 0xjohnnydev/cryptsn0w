import Foundation

enum SSHShellFailure: LocalizedError {
    case noSuccessfulInstall
    case hostSSHDisabled
    case privateKeyMissing(String)
    case pymobiledeviceMissing
    case localPortUnavailable(String)
    case forwardFailed(String)
    case terminalFailed(String)

    var errorDescription: String? {
        switch self {
        case .noSuccessfulInstall:
            "No successful install with a retained SSH key was found for this device. Run Jailbreak once with the current installer, then try again."
        case .hostSSHDisabled:
            "The latest install did not authorize this Mac for root SSH. Enable root SSH access and reinstall first."
        case .privateKeyMissing(let path):
            "The install record references an SSH key that is no longer present: \(path)"
        case .pymobiledeviceMissing:
            "The repository Python environment is missing pymobiledevice3. Run ‘make python’ and try again."
        case .localPortUnavailable(let detail):
            "CryptSn0w could not reserve a local SSH port. \(detail)"
        case .forwardFailed(let detail):
            "The USB SSH forward could not be started. \(detail)"
        case .terminalFailed(let detail):
            "Terminal could not be opened. \(detail)"
        }
    }
}
