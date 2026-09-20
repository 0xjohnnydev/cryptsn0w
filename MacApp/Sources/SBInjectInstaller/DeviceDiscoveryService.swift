import Foundation

actor DeviceDiscoveryService {
    func discover(repositoryURL: URL?) throws -> [ConnectedDevice] {
        let (executable, arguments) = try invocation(repositoryURL: repositoryURL)
        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        process.waitUntilExit()

        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let error = errorPipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: error, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw DeviceDiscoveryFailure.commandFailed(
                detail.isEmpty ? "Exit status \(process.terminationStatus)." : detail
            )
        }

        guard let records = try? JSONDecoder().decode(
            [USBMuxDeviceRecord].self,
            from: output
        ) else {
            throw DeviceDiscoveryFailure.invalidResponse
        }

        let devices = records.compactMap { record -> ConnectedDevice? in
            guard let id = record.uniqueDeviceID ?? record.identifier,
                  let model = record.productType else {
                return nil
            }
            return ConnectedDevice(
                id: id,
                name: record.deviceName ?? model,
                model: model,
                systemVersion: record.productVersion ?? "unknown",
                transport: record.connectionType ?? "usbmux"
            )
        }
        guard !devices.isEmpty else {
            throw DeviceDiscoveryFailure.noDevices
        }
        return devices.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private func invocation(repositoryURL: URL?) throws -> (URL, [String]) {
        let fileManager = FileManager.default
        if let repositoryURL {
            let python = repositoryURL.appending(path: ".venv/bin/python")
            if fileManager.isExecutableFile(atPath: python.path) {
                return (python, ["-m", "pymobiledevice3", "usbmux", "list"])
            }
        }

        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates = [
            home.appending(path: ".local/bin/pymobiledevice3"),
            URL(filePath: "/opt/homebrew/bin/pymobiledevice3"),
            URL(filePath: "/usr/local/bin/pymobiledevice3"),
        ]
        if let executable = candidates.first(where: {
            fileManager.isExecutableFile(atPath: $0.path)
        }) {
            return (executable, ["usbmux", "list"])
        }
        throw DeviceDiscoveryFailure.missingTool
    }
}
