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
    private(set) var logLines: [String] = []
    private(set) var isDiscoveringDevices = false
    private(set) var sshShellIsAvailable = false
    var isShowingError = false
    private(set) var errorTitle = "CryptexSn0w"
    private(set) var errorMessage = ""

    @ObservationIgnored private var activeProcess: Process?
    @ObservationIgnored private var installTask: Task<Void, Never>?
    @ObservationIgnored private let deviceDiscovery = DeviceDiscoveryService()
    @ObservationIgnored private let sshSession = SSHShellSessionManager()

    init() {
        repositoryURL = RepositoryLocator.locate()
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
            logLines.last ?? "Preparing the installer…"
        case .complete:
            "Sileo and the SBInject environment are ready."
        case .failed:
            logLines.last ?? "The installation stopped before completion."
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
        panel.title = "Choose the SBInject repository"
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

    func startInstall() {
        guard canStart, let repositoryURL, let selectedDevice else { return }
        state = .running
        currentStep = .connect
        logLines.removeAll(keepingCapacity: true)
        errorMessage = ""
        let shouldEnableHostSSH = enableHostSSH
        installTask = Task { [weak self] in
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

        do {
            try process.run()
            activeProcess = process
            for try await line in outputPipe.fileHandleForReading.bytes.lines {
                ingest(line)
            }
            process.waitUntilExit()
            activeProcess = nil
            if process.terminationStatus == 0 {
                currentStep = .verify
                state = .complete
                appendLog("Installation completed successfully.")
                updateSSHShellAvailability()
            } else {
                throw InstallerFailure.exitStatus(process.terminationStatus)
            }
        } catch {
            activeProcess = nil
            state = .failed
            presentError(title: "Installation Failed", error.localizedDescription)
        }
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
        logLines.append(line)
        let excess = logLines.count - 600
        if excess > 0 {
            logLines.removeFirst(excess)
        }
    }

    private func presentError(title: String, _ message: String) {
        errorTitle = title
        errorMessage = message
        isShowingError = true
    }
}
