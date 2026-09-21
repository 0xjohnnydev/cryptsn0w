import SwiftUI

struct CryptexCheckboxStyle: ToggleStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(spacing: 5) {
                Image(systemName: configuration.isOn ? "checkmark.square.fill" : "square")
                    .font(.system(size: 12))
                    .foregroundStyle(configuration.isOn ? AppTheme.accent : AppTheme.mutedInk)
                    .accessibilityHidden(true)
                configuration.label
                    .font(.system(size: 10))
            }
            .frame(minHeight: 30)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .opacity(isEnabled ? 1 : 0.5)
        .accessibilityRepresentation {
            Toggle(isOn: configuration.$isOn) {
                configuration.label
            }
            .toggleStyle(.checkbox)
            .accessibilityHint(
                "Applies to the next installation. Use Terminal for an existing SSH session.")
        }
    }
}
