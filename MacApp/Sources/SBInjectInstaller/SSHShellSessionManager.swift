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
        let scriptURL = FileManager.default.temporaryDirectory.appending(
            path: "CryptSn0w-SSH-\(UUID().uuidString).command"
        )
        let script = """
        #!/bin/zsh
        trap '/bin/rm -f -- "$0"' EXIT
        clear
        print -- 'CryptSn0w · root SSH over USB'
        \(command)
        """

        do {
            try script.write(to: scriptURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: scriptURL.path
            )
        } catch {
            throw SSHShellFailure.terminalFailed(
                "The SSH launch script could not be prepared. \(error.localizedDescription)"
            )
        }

        let opener = Process()
        let errorPipe = Pipe()
        opener.executableURL = URL(filePath: "/usr/bin/open")
        opener.arguments = ["-b", "com.apple.Terminal", scriptURL.path]
        opener.standardOutput = FileHandle.nullDevice
        opener.standardError = errorPipe
        do {
            try opener.run()
            opener.waitUntilExit()
        } catch {
            try? FileManager.default.removeItem(at: scriptURL)
            throw SSHShellFailure.terminalFailed(error.localizedDescription)
        }

        guard opener.terminationStatus == 0 else {
            let detail = String(
                decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                as: UTF8.self
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            try? FileManager.default.removeItem(at: scriptURL)
            throw SSHShellFailure.terminalFailed(
                detail.isEmpty ? "Launch Services could not open Terminal." : detail
            )
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
