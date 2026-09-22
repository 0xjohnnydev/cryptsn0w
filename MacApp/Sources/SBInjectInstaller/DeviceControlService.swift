import Foundation

@MainActor
final class DeviceControlService {
    private var forwardProcess: Process?
    private var localPort: UInt16?
    private var privateKey: URL?

    var isConnected: Bool { forwardProcess?.isRunning == true }

    func connect(privateKey key: URL, repositoryURL: URL, device: ConnectedDevice) async throws {
        disconnect()
        let python = repositoryURL.appending(path: ".venv/bin/python")
        guard FileManager.default.isExecutableFile(atPath: python.path) else {
            throw SSHShellFailure.pymobiledeviceMissing
        }
        let port = try LocalPortAllocator.reserveNumber()
        let process = Process()
        process.executableURL = python
        process.arguments = [
            "-m", "pymobiledevice3", "usbmux", "forward",
            String(port), "2222", "--serial", device.id,
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            throw SSHShellFailure.forwardFailed(error.localizedDescription)
        }
        forwardProcess = process
        localPort = port
        privateKey = key
        try await Task.sleep(for: .milliseconds(900))
        guard process.isRunning else {
            disconnect()
            throw SSHShellFailure.forwardFailed("The forward exited immediately.")
        }
    }

    func disconnect() {
        if let forwardProcess, forwardProcess.isRunning {
            forwardProcess.terminate()
        }
        forwardProcess = nil
        localPort = nil
        privateKey = nil
    }

    @discardableResult
    func customctl(_ arguments: [String]) async throws -> String {
        try await run(
            executable: URL(filePath: "/usr/bin/ssh"),
            arguments: sshArguments() + [
                "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin customctl "
                    + arguments.map(Self.quote).joined(separator: " "),
            ]
        )
    }

    func status() async throws -> JailbreakState {
        JailbreakState.parse(try await customctl(["status"]))
    }

    func applications() async throws -> [ManagedApp] {
        ManagedApp.parse(try await customctl(["apps"]))
    }

    func install(bundle: URL) async throws -> String {
        let staging = "/var/jb/var/root/.cryptsn0w-import"
        let remote = "\(staging)/\(bundle.lastPathComponent)"
        try await customctl0(["/var/jb/bin/mkdir", "-p", staging])
        _ = try await run(
            executable: URL(filePath: "/usr/bin/scp"),
            arguments: scpArguments() + [
                "-r", bundle.path, "root@127.0.0.1:\(staging)/",
            ]
        )
        let output = try await customctl(["install", remote])
        _ = try? await customctl0(["/var/jb/bin/rm", "-rf", staging])
        return output
    }

    func uninstall(identifier: String) async throws -> String {
        try await customctl(["uninstall", identifier])
    }

    @discardableResult
    private func customctl0(_ arguments: [String]) async throws -> String {
        try await run(
            executable: URL(filePath: "/usr/bin/ssh"),
            arguments: sshArguments() + [
                arguments.map(Self.quote).joined(separator: " "),
            ]
        )
    }

    private func sshArguments() -> [String] {
        guard let privateKey, let localPort else { return [] }
        return [
            "-i", privateKey.path,
            "-p", String(localPort),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "root@127.0.0.1",
        ]
    }

    private func scpArguments() -> [String] {
        guard let privateKey, let localPort else { return [] }
        return [
            "-i", privateKey.path,
            "-P", String(localPort),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
        ]
    }

    private func run(executable: URL, arguments: [String]) async throws -> String {
        guard isConnected else { throw DeviceControlFailure.notConnected }
        return try await Task.detached(priority: .userInitiated) {
            try Self.execute(executable: executable, arguments: arguments)
        }.value
    }

    private nonisolated static func execute(
        executable: URL,
        arguments: [String]
    ) throws -> String {
        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        do {
            try process.run()
        } catch {
            throw DeviceControlFailure.commandFailed(error.localizedDescription)
        }
        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let text = String(decoding: output, as: UTF8.self)
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: errorData, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let combined = detail.isEmpty
                ? text.trimmingCharacters(in: .whitespacesAndNewlines)
                : detail
            throw DeviceControlFailure.commandFailed(
                combined.isEmpty
                    ? "Exit status \(process.terminationStatus)."
                    : combined
            )
        }
        return text
    }

    private static func quote(_ value: String) -> String {
        "'\(value.replacing("'", with: "'\\''"))'"
    }
}
