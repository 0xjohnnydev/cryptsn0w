import Foundation

struct ManagedApp: Identifiable, Hashable, Sendable {
    let identifier: String
    let isPrepared: Bool
    let path: String

    var id: String { identifier }

    var name: String {
        (path as NSString).lastPathComponent
            .replacing(".app", with: "", maxReplacements: 1)
    }

    var stateDetail: String {
        isPrepared ? "registered" : "awaiting the boot daemon"
    }

    static func parse(_ output: String) -> [ManagedApp] {
        output.split(separator: "\n").compactMap { line in
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 3,
                  let prepared = fields.first(where: { $0.hasPrefix("prepared=") }),
                  let path = fields.first(where: { $0.hasPrefix("path=") })
            else { return nil }
            return ManagedApp(
                identifier: String(fields[0]),
                isPrepared: prepared.hasSuffix("=yes"),
                path: String(path.dropFirst("path=".count))
            )
        }
    }
}
