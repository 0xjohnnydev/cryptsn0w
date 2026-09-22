import SwiftUI

struct CryptexPrimaryButtonStyle: ButtonStyle {
    var fontSize: CGFloat = 17
    var minHeight: CGFloat = 48
    var tint = AppTheme.ink

    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.custom("AvenirNext-DemiBoldItalic", size: fontSize, relativeTo: .headline))
            .lineLimit(1)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity, minHeight: minHeight)
            .padding(.horizontal, 16)
            .background {
                JailbreakBrushView(
                    isEnabled: isEnabled,
                    isPressed: configuration.isPressed,
                    tint: tint
                )
            }
            .contentShape(.rect)
            .brightness(configuration.isPressed && isEnabled ? -0.06 : 0)
            .scaleEffect(
                configuration.isPressed && isEnabled && !reduceMotion ? 0.975 : 1
            )
            .animation(
                reduceMotion ? nil : .easeOut(duration: 0.12),
                value: configuration.isPressed
            )
    }
}
