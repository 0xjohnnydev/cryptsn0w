import SwiftUI

struct InstallStatusView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        VStack(spacing: 5) {
            HStack(spacing: 7) {
                if model.state == .running || model.isDiscoveringDevices {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Image(systemName: statusSymbol)
                        .foregroundStyle(statusColor)
                }
                Text(model.statusTitle)
                    .font(.headline)
            }
            Text(model.statusDetail)
                .font(.callout)
                .foregroundStyle(AppTheme.mutedInk)
                .lineLimit(1)
                .truncationMode(.middle)
            Text(model.sshStatusText)
                .font(.callout)
                .foregroundStyle(AppTheme.mutedInk)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Status")
    }

    private var statusSymbol: String {
        switch model.state {
        case .idle: "iphone.gen3.radiowaves.left.and.right"
        case .running: "arrow.down.circle"
        case .complete: "checkmark.circle.fill"
        case .failed: "exclamationmark.triangle.fill"
        }
    }

    private var statusColor: Color {
        switch model.state {
        case .idle, .running: AppTheme.accent
        case .complete: .green
        case .failed: .red
        }
    }
}
