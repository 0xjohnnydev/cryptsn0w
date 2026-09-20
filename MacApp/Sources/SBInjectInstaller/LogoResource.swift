import SwiftUI

enum LogoResource {
    static let image: NSImage = {
        let bundled = Bundle.main.url(
            forResource: "PineappleLogo",
            withExtension: "png"
        )
        let sourceTree = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "Resources/PineappleLogo.png")
        for location in [bundled, sourceTree] {
            if let location, let image = NSImage(contentsOf: location) {
                return image
            }
        }
        return NSImage(
            systemSymbolName: "iphone.and.arrow.forward",
            accessibilityDescription: "CryptexSn0w"
        ) ?? NSImage()
    }()
}
