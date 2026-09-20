import SwiftUI

struct CryptexPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(.white)
            .frame(minWidth: 116, minHeight: 36)
            .padding(.horizontal, 10)
            .background {
                Capsule()
                    .fill(
                        isEnabled
                            ? AppTheme.ink.opacity(configuration.isPressed ? 0.78 : 1)
                            : Color.secondary.opacity(0.42)
                    )
            }
            .clipShape(.capsule)
            .scaleEffect(configuration.isPressed && isEnabled ? 0.97 : 1)
            .shadow(
                color: isEnabled ? .black.opacity(0.14) : .clear,
                radius: 3,
                y: 1
            )
            .animation(
                reduceMotion ? nil : .easeOut(duration: 0.12),
                value: configuration.isPressed
            )
    }
}
