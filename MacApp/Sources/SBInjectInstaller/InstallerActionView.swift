import SwiftUI

struct InstallerActionView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        HStack {
            Label(
                model.state == .complete
                    ? "Your device is ready"
                    : "Temporary SSH keys are removed after installation",
                systemImage: model.state == .complete
                    ? "checkmark.shield.fill"
                    : "lock.shield"
            )
            .foregroundStyle(
                model.state == .complete ? .green : .secondary
            )
            Spacer()
            if model.state == .running {
                ProgressView()
                    .controlSize(.small)
            }
            Button("Jailbreak", systemImage: "bolt.fill", action: model.startInstall)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .tint(AppTheme.accent)
                .disabled(!model.canStart)
                .accessibilityInputLabels(["Jailbreak", "Start jailbreak"])
        }
        .padding()
        .background(AppTheme.panel)
        .clipShape(.rect(cornerRadius: AppTheme.cornerRadius))
    }
}
