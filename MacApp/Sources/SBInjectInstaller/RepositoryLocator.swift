import Foundation

enum RepositoryLocator {
    static func locate() -> URL? {
        let fileManager = FileManager.default
        let sourceFile = URL(filePath: #filePath)
        let startingPoints = [
            Bundle.main.bundleURL,
            URL(filePath: fileManager.currentDirectoryPath),
            sourceFile.deletingLastPathComponent(),
        ]

        for startingPoint in startingPoints {
            var candidate = startingPoint
            for _ in 0..<10 {
                if isRepository(candidate) {
                    return candidate
                }
                let parent = candidate.deletingLastPathComponent()
                if parent == candidate { break }
                candidate = parent
            }
        }
        return nil
    }

    static func isRepository(_ url: URL) -> Bool {
        FileManager.default.isExecutableFile(
            atPath: url.appending(
                path: "Dopamine-CryptexBootstrap/setup.sh"
            ).path
        )
    }
}
