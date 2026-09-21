import SwiftUI

struct DeviceConnectionBadgeView: View {
    let isDiscovering: Bool
    let isConnected: Bool

    var body: some View {
        HStack(spacing: 6) {
            if isDiscovering {
                ProgressView()
                    .controlSize(.mini)
                    .tint(AppTheme.accent)
            } else {
                Image(systemName: symbol)
                    .symbolRenderingMode(.hierarchical)
            }

            Text(title)
                .font(AppTheme.labelFont)
                .tracking(0.4)
        }
        .foregroundStyle(color)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
    }

    private var title: String {
        if isDiscovering { return "SCANNING" }
        return isConnected ? "CONNECTED" : "WAITING"
    }

    private var symbol: String {
        isConnected ? "checkmark.circle.fill" : "circle.dotted"
    }

    private var color: Color {
        isConnected ? AppTheme.success : AppTheme.accent
    }
}
