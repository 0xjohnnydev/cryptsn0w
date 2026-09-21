import SwiftUI

enum LogoResource {
    static let image: NSImage = {
        let bundled = Bundle.main.url(
            forResource: "PineappleBrushLogo",
            withExtension: "png"
        )
        let sourceTree = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "Resources/PineappleBrushLogo.png")
        for location in [bundled, sourceTree] {
            if let location, let image = NSImage(contentsOf: location) {
                return image
            }
        }
        return NSImage(
            systemSymbolName: "iphone.and.arrow.forward",
            accessibilityDescription: "CryptSn0w"
        ) ?? NSImage()
    }()
}
