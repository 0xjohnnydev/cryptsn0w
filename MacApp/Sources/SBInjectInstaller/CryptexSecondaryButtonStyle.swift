import SwiftUI

struct CryptexSecondaryButtonStyle: ButtonStyle {
    enum Size {
        case regular
        case compact

        var font: Font {
            switch self {
            case .regular:
                .custom("AvenirNext-DemiBold", size: 14, relativeTo: .body)
            case .compact:
                .custom("AvenirNext-DemiBold", size: 11, relativeTo: .caption)
            }
        }

        var height: CGFloat {
            switch self {
            case .regular: 34
            case .compact: 22
            }
        }

        var horizontalPadding: CGFloat {
            switch self {
            case .regular: 18
            case .compact: 10
            }
        }

        var cornerRadius: CGFloat {
            switch self {
            case .regular: 9
            case .compact: 6
            }
        }
    }

    var size = Size.regular
    var expands = false
    var flat = false

    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(size.font)
            .tracking(0.2)
            .lineLimit(1)
            .fixedSize(horizontal: !expands, vertical: false)
            .foregroundStyle(
                isEnabled ? AppTheme.accentDeep : AppTheme.faintInk
            )
            .padding(.horizontal, size.horizontalPadding)
            .frame(
                maxWidth: expands ? .infinity : nil,
                minHeight: size.height
            )
            .background(
                RoundedRectangle(cornerRadius: size.cornerRadius, style: .continuous)
                    .fill(fill(isPressed: configuration.isPressed))
            )
            .overlay {
                if !flat {
                    RoundedRectangle(cornerRadius: size.cornerRadius, style: .continuous)
                        .strokeBorder(
                            isEnabled
                                ? AppTheme.accent.opacity(configuration.isPressed ? 0.85 : 0.55)
                                : AppTheme.strongDivider,
                            lineWidth: 1
                        )
                }
            }
            .contentShape(.rect)
            .scaleEffect(
                configuration.isPressed && isEnabled && !reduceMotion ? 0.97 : 1
            )
            .animation(
                reduceMotion ? nil : .easeOut(duration: 0.12),
                value: configuration.isPressed
            )
    }

    private func fill(isPressed: Bool) -> Color {
        guard isEnabled else {
            return flat ? AppTheme.strongDivider.opacity(0.3) : AppTheme.paper.opacity(0.5)
        }
        if flat {
            return AppTheme.accent.opacity(isPressed ? 0.26 : 0.15)
        }
        return AppTheme.paperHighlight.opacity(isPressed ? 0.55 : 1)
    }
}
