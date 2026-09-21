import SwiftUI

struct DeviceInstallView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        VStack(alignment: .leading, spacing: AppTheme.spacing) {
            DevicePickerView(model: model)

            SSHAccessToggleView(model: model)

            HStack(alignment: .center, spacing: 22) {
                VStack(alignment: .leading, spacing: AppTheme.tightSpacing) {
                    HStack {
                        Text("PROGRESS")
                            .font(AppTheme.labelFont)
                            .tracking(0.8)
                            .foregroundStyle(AppTheme.mutedInk)

                        Spacer()

                        Text(model.progressText)
                            .font(AppTheme.labelFont.monospacedDigit())
                            .foregroundStyle(AppTheme.accent)
                    }

                    PanguProgressBar(progress: model.progress, state: model.state)
                }

                Button(model.actionTitle, action: model.startInstall)
                    .buttonStyle(CryptexPrimaryButtonStyle())
                    .frame(width: 168)
                    .disabled(!model.canStart)
                    .accessibilityInputLabels(["Jailbreak", "Install"])
            }
        }
    }
}
