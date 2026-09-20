import AppKit
import Foundation
import Observation

@MainActor
@Observable
final class InstallerModel {
    var deviceIdentifier = ""
    private(set) var repositoryURL: URL?
    private(set) var state = InstallState.idle
    private(set) var currentStep = InstallStep.connect
    private(set) var logLines: [String] = []
    var isShowingError = false
    private(set) var errorMessage = ""

    @ObservationIgnored private var activeProcess: Process?
    @ObservationIgnored private var installTask: Task<Void, Never>?

    init() {
        repositoryURL = RepositoryLocator.locate()
    }

    var statusTitle: String {
        switch state {
        case .idle: "Ready to jailbreak"
        case .running: currentStep.title
        case .complete: "Jailbreak complete"
        case .failed: "Installation stopped"
        }
    }

    var canStart: Bool {
        state != .running && repositoryURL != nil
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
        } else {
            presentError(
                "That folder does not contain Dopamine-CryptexBootstrap/setup.sh."
            )
        }
    }

    func startInstall() {
        guard canStart, let repositoryURL else { return }
        state = .running
        currentStep = .connect
        logLines.removeAll(keepingCapacity: true)
        errorMessage = ""
        let requestedDevice = deviceIdentifier.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        installTask = Task { [weak self] in
            await self?.runInstaller(
                repositoryURL: repositoryURL,
                requestedDevice: requestedDevice
            )
        }
    }

    private func runInstaller(
        repositoryURL: URL,
        requestedDevice: String
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
            } else {
                throw InstallerFailure.exitStatus(process.terminationStatus)
            }
        } catch {
            activeProcess = nil
            state = .failed
            presentError(error.localizedDescription)
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

    private func presentError(_ message: String) {
        errorMessage = message
        isShowingError = true
    }
}
