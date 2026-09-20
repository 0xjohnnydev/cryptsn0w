import SwiftUI

struct CryptexPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(.white)
            .frame(minWidth: 112, minHeight: 34)
            .padding(.horizontal, 8)
            .background(
                isEnabled
                    ? AppTheme.ink.opacity(configuration.isPressed ? 0.78 : 1)
                    : Color.secondary.opacity(0.42)
            )
            .clipShape(.capsule)
    }
}
