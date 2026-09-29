import AppKit
import Foundation
import Observation

@MainActor
@Observable
final class InstallerModel {
    private(set) var devices: [ConnectedDevice] = []
    var selectedDeviceIdentifier: String?
    var enableHostSSH = false
    private(set) var repositoryURL: URL?
    private(set) var state = InstallState.idle
    private(set) var currentStep = InstallStep.connect
    private(set) var lastLogLine: String?
    private(set) var logFileURL: URL?
    private(set) var isDiscoveringDevices = false
    private(set) var sshShellIsAvailable = false
    var isShowingError = false
    private(set) var errorTitle = "CryptSn0w"
    private(set) var errorMessage = ""

    @ObservationIgnored private let deviceDiscovery = DeviceDiscoveryService()
    @ObservationIgnored private let sshSession = SSHShellSessionManager()

    init(repositoryURL: URL? = RepositoryLocator.locate()) {
        self.repositoryURL = repositoryURL
    }

    var statusTitle: String {
        if isDiscoveringDevices && state == .idle {
            return "Looking for connected devices"
        }
        return switch state {
        case .idle: "Ready to jailbreak"
        case .running: currentStep.title
        case .complete: "Jailbreak complete"
        case .failed: "Installation stopped"
        }
    }

    var canStart: Bool {
        state != .running && repositoryURL != nil && selectedDevice != nil
    }

    var canOpenSSHShell: Bool {
        state != .running && sshShellIsAvailable
    }

    var canShowLog: Bool {
        logFileURL != nil
    }

    var selectedDevice: ConnectedDevice? {
        devices.first { $0.id == selectedDeviceIdentifier }
    }

    var statusDetail: String {
        switch state {
        case .idle:
            if repositoryURL == nil {
                "Choose the installer repository from the Device menu."
            } else {
                selectedDevice?.detail ?? "Connect and unlock a paired iPhone."
            }
        case .running:
            lastLogLine ?? "Preparing the installer…"
        case .complete:
            "Sileo and the SBInject environment are ready."
        case .failed:
            lastLogLine ?? "The installation stopped before completion."
        }
    }

    var progress: Double {
        switch state {
        case .idle: 0
        case .running, .failed: currentStep.progress
        case .complete: 1
        }
    }

    var progressText: String {
        progress.formatted(.percent.precision(.fractionLength(0)))
    }

    var actionTitle: String {
        switch state {
        case .idle, .failed: "Jailbreak"
        case .running: "Installing…"
        case .complete: "Reinstall"
        }
    }

    func chooseRepository() {
        let panel = NSOpenPanel()
        panel.title = "Choose the CryptSn0w repository"
        panel.prompt = "Choose"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let selected = panel.url else { return }
        if RepositoryLocator.isRepository(selected) {
            repositoryURL = selected
            requestDeviceRefresh()
        } else {
            presentError(
                title: "Repository Not Found",
                "That folder does not contain Dopamine-CryptexBootstrap/setup.sh."
            )
        }
    }

    func requestDeviceRefresh() {
        Task { [weak self] in
            await self?.refreshDevices()
        }
    }

    func refreshDevices() async {
        guard !isDiscoveringDevices else { return }
        isDiscoveringDevices = true
        defer { isDiscoveringDevices = false }

        do {
            let discovered = try await deviceDiscovery.discover(
                repositoryURL: repositoryURL
            )
            let previousSelection = selectedDeviceIdentifier
            devices = discovered
            if let previousSelection,
               discovered.contains(where: { $0.id == previousSelection }) {
                selectedDeviceIdentifier = previousSelection
            } else {
                selectedDeviceIdentifier = discovered.first?.id
            }
            updateSSHShellAvailability()
        } catch {
            devices = []
            selectedDeviceIdentifier = nil
            sshShellIsAvailable = false
            presentError(title: "Device Discovery Failed", error.localizedDescription)
        }
    }

    func updateSSHShellAvailability() {
        guard let repositoryURL, let selectedDevice else {
            sshShellIsAvailable = false
            return
        }
        sshShellIsAvailable = sshSession.hasCredential(
            repositoryURL: repositoryURL,
            deviceIdentifier: selectedDevice.id
        )
    }

    func openSSHShell() {
        guard let repositoryURL, let selectedDevice else { return }
        Task { [weak self] in
            guard let self else { return }
            do {
                try await sshSession.open(
                    repositoryURL: repositoryURL,
                    device: selectedDevice
                )
            } catch {
                presentError(title: "SSH Shell Unavailable", error.localizedDescription)
            }
        }
    }

    func showLog() {
        guard let logFileURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([logFileURL])
    }

    func startInstall() {
        guard canStart, let repositoryURL, let selectedDevice else { return }
        state = .running
        currentStep = .connect
        lastLogLine = nil
        logFileURL = nil
        errorMessage = ""
        let shouldEnableHostSSH = enableHostSSH
        Task { [weak self] in
            await self?.runInstaller(
                repositoryURL: repositoryURL,
                requestedDevice: selectedDevice.id,
                enableHostSSH: shouldEnableHostSSH
            )
        }
    }

    private func runInstaller(
        repositoryURL: URL,
        requestedDevice: String,
        enableHostSSH: Bool
    ) async {
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = repositoryURL.appending(
            path: "Dopamine-CryptexBootstrap/setup.sh"
        )
        var arguments = ["--install"]
        if !requestedDevice.isEmpty {
            arguments.append(contentsOf: ["--device", requestedDevice])
        }
        if enableHostSSH {
            arguments.append("--enable-host-ssh")
        }
        process.arguments = arguments
        process.currentDirectoryURL = repositoryURL
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        process.environment = ProcessInfo.processInfo.environment.merging(
            ["NSUnbufferedIO": "YES"],
            uniquingKeysWith: { _, new in new }
        )

        var logHandle: FileHandle?
        defer {
            if let logHandle {
                try? logHandle.synchronize()
                try? logHandle.close()
            }
        }

        do {
            let logFile = try createLogFile(deviceIdentifier: requestedDevice)
            logFileURL = logFile.url
            logHandle = logFile.handle
            writeLog(
                """
                CryptSn0w install log
                Started: \(Date().formatted(.iso8601))
                Repository: \(repositoryURL.path)
                Device: \(requestedDevice)
                Command: \(process.executableURL?.path ?? "setup.sh") \(arguments.joined(separator: " "))

                """,
                to: logFile.handle
            )

            try process.run()
            for try await line in outputPipe.fileHandleForReading.bytes.lines {
                writeLog("\(line)\n", to: logFile.handle)
                ingest(line)
            }
            process.waitUntilExit()
            writeLog(
                "\nFinished: \(Date().formatted(.iso8601))\nExit status: \(process.terminationStatus)\n",
                to: logFile.handle
            )
            if process.terminationStatus == 0 {
                currentStep = .verify
                state = .complete
                appendLog("Installation completed successfully.")
                updateSSHShellAvailability()
            } else {
                throw InstallerFailure.exitStatus(process.terminationStatus)
            }
        } catch {
            state = .failed
            if let logHandle {
                writeLog("\nGUI error: \(error.localizedDescription)\n", to: logHandle)
            }
            let logLocation = logFileURL.map {
                "\n\nLog file: \($0.path)"
            } ?? ""
            presentError(
                title: "Installation Failed",
                error.localizedDescription + logLocation
            )
        }
    }

    private func createLogFile(
        deviceIdentifier: String
    ) throws -> (url: URL, handle: FileHandle) {
        let directory = FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/Logs/CryptexSn0w", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSS"
        let device = deviceIdentifier.replacingOccurrences(
            of: "[^A-Za-z0-9._-]",
            with: "_",
            options: .regularExpression
        )
        let url = directory.appending(
            path: "install-\(formatter.string(from: Date()))-\(device).log"
        )
        guard FileManager.default.createFile(
            atPath: url.path,
            contents: nil
        ) else {
            throw CocoaError(.fileWriteUnknown)
        }
        return (url, try FileHandle(forWritingTo: url))
    }

    private func writeLog(_ text: String, to handle: FileHandle) {
        try? handle.write(contentsOf: Data(text.utf8))
    }

    private func ingest(_ line: String) {
        appendLog(line)
        if line.contains("stage-install.json") {
            currentStep = .transferStage
        } else if line.contains("SpringBoard.app") ||
                    line.contains("Preferences.app") {
            currentStep = .copySystemApps
        } else if line.contains("Building fixed-trust Cryptex") {
            currentStep = .buildFinal
        } else if line.contains("final-install.json") {
            currentStep = .installFinal
        } else if line.contains("system-sileo-icon") ||
                    line.contains("Install flow succeeded") {
            currentStep = .verify
        }
    }

    private func appendLog(_ line: String) {
        guard !line.isEmpty else { return }
        lastLogLine = line
    }

    private func presentError(title: String, _ message: String) {
        errorTitle = title
        errorMessage = message
        isShowingError = true
    }
}
