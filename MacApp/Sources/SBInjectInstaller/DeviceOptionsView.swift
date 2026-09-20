import SwiftUI

struct DeviceOptionsView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        VStack(alignment: .leading, spacing: AppTheme.compactSpacing) {
            Text("Connect and unlock a paired iPhone, then press Jailbreak. The phone will not reboot.")
                .font(.body)
            HStack(spacing: AppTheme.compactSpacing) {
                TextField(
                    "Device UDID (optional; auto-detects one connected phone)",
                    text: $model.deviceIdentifier
                )
                .textFieldStyle(.roundedBorder)
                .disabled(model.state == .running)
                Button("Choose Repository…", action: model.chooseRepository)
                    .disabled(model.state == .running)
            }
            LabeledContent("Repository") {
                Text(model.repositoryURL?.path ?? "Not found — choose the repository folder")
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(
                        model.repositoryURL == nil ? .red : .secondary
                    )
            }
        }
        .padding()
        .background(AppTheme.panel)
        .clipShape(.rect(cornerRadius: AppTheme.cornerRadius))
    }
}
