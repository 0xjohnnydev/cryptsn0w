import Foundation
import Testing
@testable import CryptSn0w

@Suite(.serialized, .timeLimit(.minutes(1)))
@MainActor
struct CryptSn0wTests {
    @Test func discoveryPrefersUSBAndSkipsIncompleteRecords() async throws {
        let fixture = try Fixture(query: #"""
        [
          {"UniqueDeviceID":"a","ProductType":"test-model-a","DeviceName":"Alpha","ConnectionType":"Network"},
          {"UniqueDeviceID":"a","ProductType":"test-model-a","DeviceName":"Alpha","ConnectionType":"USB"},
          {"Identifier":"b","ProductType":"test-model-b","DeviceName":"Beta"},
          {"UniqueDeviceID":"missing-model"},
          {"ProductType":"missing-id"}
        ]
        """#)
        defer { fixture.remove() }
        let devices = try await DeviceDiscoveryService().discover(repositoryURL: fixture.root)
        #expect(devices.map(\.id) == ["a", "b"])
        #expect(devices[0].transport == "USB")
        #expect(devices[1].transport == "usbmux")
        #expect(devices[1].systemVersion == "unknown")
    }

    @Test func discoveryDrainsBothPipes() async throws {
        let name = String(repeating: "n", count: 200_000)
        let fixture = try Fixture(
            query: "[{\"UniqueDeviceID\":\"a\",\"ProductType\":\"test-model\",\"DeviceName\":\"\(name)\"}]",
            queryError: String(repeating: "diagnostic\n", count: 20_000)
        )
        defer { fixture.remove() }
        let devices = try await DeviceDiscoveryService().discover(repositoryURL: fixture.root)
        #expect(devices.first?.name == name)
    }

    @Test func discoveryReportsErrors() async throws {
        for (query, exitCode, expected) in [
            ("not json", 0, "invalid"),
            ("[]", 0, "empty"),
            ("[]", 3, "command")
        ] {
            let fixture = try Fixture(query: query, queryError: "query failed\n", queryExit: exitCode)
            defer { fixture.remove() }
            do {
                _ = try await DeviceDiscoveryService().discover(repositoryURL: fixture.root)
                Issue.record("Expected discovery to fail: \(expected)")
            } catch let error as DeviceDiscoveryFailure {
                switch error {
                case .invalidResponse: #expect(expected == "invalid")
                case .noDevices: #expect(expected == "empty")
                case .commandFailed(let detail):
                    #expect(expected == "command")
                    #expect(detail == "query failed")
                default: Issue.record("Unexpected discovery error: \(error)")
                }
            }
        }
    }

    @Test func fullLogSurvivesShortStatusDisplay() async throws {
        let output = (0..<650).map { "line-\($0)" }.joined(separator: "\n") + "\n"
        let fixture = try Fixture(installOutput: output)
        defer { fixture.remove() }
        let model = InstallerModel(repositoryURL: fixture.root)
        await model.refreshDevices()
        #expect(model.canStart)
        model.startInstall()
        try await waitForCompletion(model)
        let logURL = try #require(model.logFileURL)
        defer { try? FileManager.default.removeItem(at: logURL) }
        #expect(model.state == .complete)
        #expect(model.lastLogLine == "Installation completed successfully.")
        let log = try String(contentsOf: logURL, encoding: .utf8)
        #expect(log.contains("line-0\n"))
        #expect(log.contains("line-649\n"))
        #expect(log.contains("Exit status: 0"))
    }

    @Test func failedCommandKeepsItsLog() async throws {
        let fixture = try Fixture(installOutput: "fixture failure\n", installExit: 7)
        defer { fixture.remove() }
        let model = InstallerModel(repositoryURL: fixture.root)
        await model.refreshDevices()
        model.startInstall()
        try await waitForCompletion(model)
        let logURL = try #require(model.logFileURL)
        defer { try? FileManager.default.removeItem(at: logURL) }
        #expect(model.state == .failed)
        #expect(model.lastLogLine == "fixture failure")
        #expect(model.errorMessage.contains("status 7"))
        #expect(model.errorMessage.contains(logURL.path))
        #expect(try String(contentsOf: logURL, encoding: .utf8).contains("Exit status: 7"))
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["CRYPTSN0W_TEST_REPOSITORY"] != nil))
    func liveDeviceDiscovery() async throws {
        let environment = ProcessInfo.processInfo.environment
        let repository = try #require(environment["CRYPTSN0W_TEST_REPOSITORY"])
        let expectedID = try #require(environment["CRYPTSN0W_TEST_DEVICE"])
        let discovery = DeviceDiscoveryService()
        for _ in 0..<5 {
            let devices = try await discovery.discover(repositoryURL: URL(filePath: repository))
            #expect(devices.contains { $0.id == expectedID })
        }
    }

    private func waitForCompletion(_ model: InstallerModel) async throws {
        for _ in 0..<250 {
            if model.state != .running { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        try #require(model.state != .running, "Fixture command did not finish")
    }
}

private struct Fixture {
    let root: URL

    init(
        query: String = #"[{"UniqueDeviceID":"fixture-device","ProductType":"test-model"}]"#,
        queryError: String = "",
        queryExit: Int = 0,
        installOutput: String = "",
        installExit: Int = 0
    ) throws {
        root = FileManager.default.temporaryDirectory.appending(path: "CryptSn0wTests-\(UUID())")
        try writeCommand(".venv/bin/python", output: query, error: queryError, exitCode: queryExit)
        try writeCommand("Dopamine-CryptexBootstrap/setup.sh", output: installOutput, error: "", exitCode: installExit)
    }

    private func writeCommand(_ relativePath: String, output: String, error: String, exitCode: Int) throws {
        let command = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: command.deletingLastPathComponent(), withIntermediateDirectories: true)
        let script = """
        #!/bin/sh
        /bin/cat "$0.stderr" >&2
        /bin/cat "$0.stdout"
        exit \(exitCode)
        """
        try script.write(to: command, atomically: true, encoding: .utf8)
        try output.write(toFile: command.path + ".stdout", atomically: true, encoding: .utf8)
        try error.write(toFile: command.path + ".stderr", atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: command.path)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}
