import SwiftUI

enum AppTheme {
    static let accent = Color(red: 0.32, green: 0.46, blue: 0.025)
    static let accentBright = Color(red: 0.65, green: 0.90, blue: 0.10)
    static let accentDeep = Color(red: 0.20, green: 0.32, blue: 0.015)
    static let accentSoft = Color(red: 0.46, green: 0.63, blue: 0.09)

    static let ink = Color(red: 0.055, green: 0.065, blue: 0.08)
    static let softInk = Color(red: 0.16, green: 0.18, blue: 0.21)
    static let mutedInk = Color(red: 0.34, green: 0.37, blue: 0.41)
    static let faintInk = Color(red: 0.50, green: 0.53, blue: 0.57)

    static let paper = Color(red: 0.95, green: 0.96, blue: 0.93)
    static let paperHighlight = Color(red: 0.995, green: 1.00, blue: 0.98)
    static let strongDivider = Color.black.opacity(0.16)
    static let progressTrack = Color.black.opacity(0.12)

    static let success = Color(red: 0.08, green: 0.55, blue: 0.31)
    static let failure = Color(red: 0.78, green: 0.17, blue: 0.20)

    static let backgroundGradient = LinearGradient(
        colors: [paperHighlight, paper, Color(red: 0.93, green: 0.95, blue: 0.89)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let accentGradient = LinearGradient(
        colors: [accentBright, accent, accentDeep],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let brandFont = Font.custom("AvenirNext-DemiBold", size: 17, relativeTo: .headline)
    static let controlFont = Font.custom("AvenirNext-Medium", size: 13, relativeTo: .body)
    static let detailFont = Font.system(size: 11)
    static let labelFont = Font.system(size: 10, weight: .medium, design: .monospaced)
    static let rowIconWidth = 24.0
    static let rowSpacing = 10.0
    static let spacing = 12.0
    static let compactSpacing = 8.0
    static let tightSpacing = 5.0
    static let contentHorizontalPadding = 28.0
    static let contentTopPadding = 16.0
    static let contentBottomPadding = 16.0
    static let windowWidth = 640.0
    static let windowHeight = 350.0
    static let manageWindowHeight = 470.0
}
