import AppKit
import Foundation

@MainActor
final class SSHShellSessionManager {
    private var forwardProcess: Process?
    private var forwardErrorPipe: Pipe?

    func hasCredential(
        repositoryURL: URL,
        deviceIdentifier: String
    ) -> Bool {
        (try? latestPrivateKey(
            repositoryURL: repositoryURL,
            deviceIdentifier: deviceIdentifier
        )) != nil
    }

    func open(repositoryURL: URL, device: ConnectedDevice) async throws {
        let privateKey = try latestPrivateKey(
            repositoryURL: repositoryURL,
            deviceIdentifier: device.id
        )
        let python = repositoryURL.appending(path: ".venv/bin/python")
        guard FileManager.default.isExecutableFile(atPath: python.path) else {
            throw SSHShellFailure.pymobiledeviceMissing
        }

        stopForward()
        let localPort = try LocalPortAllocator.reserveNumber()
        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = python
        process.arguments = [
            "-m", "pymobiledevice3", "usbmux", "forward",
            String(localPort), "2222", "--serial", device.id,
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorPipe

        do {
            try process.run()
        } catch {
            throw SSHShellFailure.forwardFailed(error.localizedDescription)
        }
        forwardProcess = process
        forwardErrorPipe = errorPipe

        try await Task.sleep(for: .milliseconds(650))
        guard process.isRunning else {
            let detail = String(
                decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                as: UTF8.self
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            forwardProcess = nil
            forwardErrorPipe = nil
            throw SSHShellFailure.forwardFailed(
                detail.isEmpty ? "The forward process exited immediately." : detail
            )
        }

        do {
            try openTerminal(privateKey: privateKey, localPort: localPort)
        } catch {
            stopForward()
            throw error
        }
    }

    private func latestPrivateKey(
        repositoryURL: URL,
        deviceIdentifier: String
    ) throws -> URL {
        let runs = repositoryURL.appending(
            path: "Dopamine-upstream/CryptexBootstrap/out/runs"
        )
        let runDirectories = (try? FileManager.default.contentsOfDirectory(
            at: runs,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []

        for runDirectory in runDirectories.sorted(
            by: { $0.lastPathComponent > $1.lastPathComponent }
        ) {
            let summaryURL = runDirectory.appending(path: "flow-summary.json")
            guard let data = try? Data(contentsOf: summaryURL),
                  let summary = try? JSONDecoder().decode(
                    FlowSummary.self,
                    from: data
                  ),
                  summary.device.udid.caseInsensitiveCompare(deviceIdentifier) == .orderedSame else {
                continue
            }
            guard summary.result == "success" else {
                throw SSHShellFailure.noSuccessfulInstall
            }
            guard let keyPath = summary.hostSSHPrivateKey else {
                throw SSHShellFailure.hostSSHDisabled
            }
            let keyURL = if (keyPath as NSString).isAbsolutePath {
                URL(filePath: keyPath).standardizedFileURL
            } else {
                runDirectory.appending(path: keyPath).standardizedFileURL
            }
            guard FileManager.default.isReadableFile(atPath: keyURL.path) else {
                throw SSHShellFailure.privateKeyMissing(keyURL.path)
            }
            return keyURL
        }
        throw SSHShellFailure.noSuccessfulInstall
    }

    private func openTerminal(privateKey: URL, localPort: UInt16) throws {
        let command = [
            "/usr/bin/ssh",
            "-i", shellQuote(privateKey.path),
            "-p", String(localPort),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "root@127.0.0.1",
        ].joined(separator: " ")
        let escapedCommand = command
            .replacing("\\", with: "\\\\")
            .replacing("\"", with: "\\\"")
        let source = """
        tell application "Terminal"
            activate
            do script "\(escapedCommand)"
        end tell
        """
        guard let script = NSAppleScript(source: source) else {
            throw SSHShellFailure.terminalFailed("The Terminal request was invalid.")
        }
        var errorInfo: NSDictionary?
        script.executeAndReturnError(&errorInfo)
        if let errorInfo {
            let detail = errorInfo[NSAppleScript.errorMessage] as? String
                ?? "macOS rejected the Terminal automation request."
            throw SSHShellFailure.terminalFailed(detail)
        }
    }

    private func shellQuote(_ value: String) -> String {
        "'\(value.replacing("'", with: "'\\''"))'"
    }

    private func stopForward() {
        if let forwardProcess, forwardProcess.isRunning {
            forwardProcess.terminate()
        }
        forwardProcess = nil
        forwardErrorPipe = nil
    }
}
