import Foundation

actor DeviceDiscoveryService {
    func discover(repositoryURL: URL?) async throws -> [ConnectedDevice] {
        let (executable, arguments) = try invocation(repositoryURL: repositoryURL)
        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()

        // Drain both pipes before waiting. Either stream can fill its pipe.
        async let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        async let error = errorPipe.fileHandleForReading.readDataToEndOfFile()
        let (outputData, errorData) = await (output, error)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: errorData, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw DeviceDiscoveryFailure.commandFailed(
                detail.isEmpty ? "Exit status \(process.terminationStatus)." : detail
            )
        }

        guard let records = try? JSONDecoder().decode(
            [USBMuxDeviceRecord].self,
            from: outputData
        ) else {
            throw DeviceDiscoveryFailure.invalidResponse
        }

        var devices: [String: ConnectedDevice] = [:]
        for record in records {
            guard let id = record.uniqueDeviceID ?? record.identifier,
                  let model = record.productType else {
                continue
            }
            let candidate = ConnectedDevice(
                id: id,
                name: record.deviceName ?? model,
                model: model,
                systemVersion: record.productVersion ?? "unknown",
                transport: record.connectionType ?? "usbmux"
            )
            if let existing = devices[id],
               Self.transportPriority(existing.transport)
                <= Self.transportPriority(candidate.transport) {
                continue
            }
            devices[id] = candidate
        }
        guard !devices.isEmpty else {
            throw DeviceDiscoveryFailure.noDevices
        }
        return devices.values.sorted {
            $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    private static func transportPriority(_ transport: String) -> Int {
        transport.lowercased() == "usb" ? 0 : 1
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
