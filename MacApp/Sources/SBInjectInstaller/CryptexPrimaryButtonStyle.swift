import SwiftUI

struct CryptexPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.custom("AvenirNext-DemiBoldItalic", size: 17, relativeTo: .headline))
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity, minHeight: 48)
            .padding(.horizontal, 16)
            .background {
                JailbreakBrushView(isEnabled: isEnabled, isPressed: configuration.isPressed)
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
