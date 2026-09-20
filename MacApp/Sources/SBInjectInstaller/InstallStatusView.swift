import SwiftUI

struct InstallStatusView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        HStack(spacing: 11) {
            if model.state == .running || model.isDiscoveringDevices {
                ProgressView()
                    .controlSize(.small)
            } else {
                Image(systemName: statusSymbol)
                    .font(.title3)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(statusColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(model.statusTitle)
                    .font(.headline)
                Text(model.statusDetail)
                    .font(.callout)
                    .foregroundStyle(AppTheme.mutedInk)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: AppTheme.compactSpacing)

            if model.state != .idle {
                Text(model.progressText)
                    .font(.headline.monospacedDigit())
                    .foregroundStyle(statusColor)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: AppTheme.cornerRadius)
                .fill(AppTheme.surface)
                .stroke(AppTheme.divider, lineWidth: 1)
        }
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
        case .complete: AppTheme.success
        case .failed: AppTheme.failure
        }
    }
}
