import SwiftUI

struct InstallStatusView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        HStack(spacing: AppTheme.rowSpacing) {
            ZStack {
                PanguBrushStrokeShape()
                    .fill(statusColor.opacity(0.12))
                    .frame(width: 29, height: 24)

                if model.state == .running || model.isDiscoveringDevices {
                    ProgressView()
                        .controlSize(.small)
                        .tint(statusColor)
                } else {
                    Image(systemName: statusSymbol)
                        .font(.system(size: 15))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(statusColor)
                }
            }
            .frame(width: AppTheme.rowIconWidth, height: 32)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(model.statusTitle)
                    .font(AppTheme.controlFont)
                Text(model.statusDetail)
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.mutedInk)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: AppTheme.compactSpacing)

            if model.canManage, model.state != .running {
                Button(action: model.enterManageMode) {
                    Label("Manage", systemImage: "slider.horizontal.3")
                        .labelStyle(.titleAndIcon)
                        .imageScale(.small)
                }
                .buttonStyle(
                    CryptexSecondaryButtonStyle(expands: true, flat: true)
                )
                .frame(width: 124)
                .help("Open the jailbreak management panel")
            }

            if model.canShowLog {
                Button("Show Log", systemImage: "doc.text") {
                    model.showLog()
                }
                .controlSize(.small)
                .help("Reveal the complete installer log in Finder")
            }

            if model.state != .idle {
                Text(model.progressText)
                    .font(.callout.monospacedDigit())
                    .bold()
                    .foregroundStyle(statusColor)
            }
        }
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Status: \(model.statusTitle). \(model.statusDetail)")
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
