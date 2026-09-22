import Foundation

enum BundleImporter {
    struct Import: Sendable {
        let bundle: URL
        let scratch: URL?
    }

    static func prepare(_ dropped: URL) throws -> Import {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(
            atPath: dropped.path,
            isDirectory: &isDirectory
        ) else {
            throw DeviceControlFailure.unsupportedDrop
        }

        if isDirectory.boolValue, dropped.pathExtension.lowercased() == "app" {
            return Import(bundle: dropped, scratch: nil)
        }
        guard dropped.pathExtension.lowercased() == "ipa" else {
            throw DeviceControlFailure.unsupportedDrop
        }

        let scratch = FileManager.default.temporaryDirectory
            .appending(path: "CryptSn0w-IPA-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: scratch,
            withIntermediateDirectories: true
        )
        do {
            try expand(archive: dropped, into: scratch)
        } catch {
            try? FileManager.default.removeItem(at: scratch)
            throw error
        }

        let payload = scratch.appending(path: "Payload")
        let bundles = (try? FileManager.default.contentsOfDirectory(
            at: payload,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        guard let bundle = bundles.first(where: {
            $0.pathExtension.lowercased() == "app"
        }) else {
            try? FileManager.default.removeItem(at: scratch)
            throw DeviceControlFailure.noBundleInArchive
        }
        return Import(bundle: bundle, scratch: scratch)
    }

    private static func expand(archive: URL, into directory: URL) throws {
        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = URL(filePath: "/usr/bin/ditto")
        process.arguments = ["-x", "-k", archive.path, directory.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorPipe
        do {
            try process.run()
        } catch {
            throw DeviceControlFailure.archiveFailed(error.localizedDescription)
        }
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: errorData, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw DeviceControlFailure.archiveFailed(
                detail.isEmpty ? "ditto exited \(process.terminationStatus)." : detail
            )
        }
    }
}
