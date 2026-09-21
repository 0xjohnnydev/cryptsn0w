import SwiftUI

struct SSHAccessToggleView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        HStack(spacing: AppTheme.rowSpacing) {
            Image(systemName: "terminal")
                .font(.system(size: 15))
                .foregroundStyle(AppTheme.accent)
                .frame(width: AppTheme.rowIconWidth)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text("SSH access")
                    .font(.custom("AvenirNext-Medium", size: 12, relativeTo: .body))
                Text(availabilityDetail)
                    .font(.system(size: 10))
                    .foregroundStyle(AppTheme.mutedInk)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            Toggle("Enable on install", isOn: $model.enableHostSSH)
                .toggleStyle(CryptexCheckboxStyle())
                .disabled(model.state == .running)
                .help("Keep a device-specific key for this Mac during installation")

            Button("Terminal", systemImage: "terminal", action: model.openSSHShell)
                .font(.system(size: 10, weight: .medium))
                .buttonStyle(.plain)
                .foregroundStyle(model.canOpenSSHShell ? AppTheme.accent : AppTheme.faintInk)
                .disabled(!model.canOpenSSHShell || model.isDiscoveringDevices)
                .help(
                    model.canOpenSSHShell
                        ? "Open the selected device’s SSH session in Terminal" : availabilityDetail)
                .accessibilityLabel("Open SSH session in Terminal")
        }
        .frame(minHeight: 36)
    }

    private var availabilityDetail: String {
        if model.state == .running { return "Available when installation finishes" }
        if model.isDiscoveringDevices { return "Checking the connected device…" }
        if model.selectedDevice == nil { return "Connect a device to open a session" }
        if model.canOpenSSHShell { return "Ready to open in Terminal" }
        return "Enable SSH and install to save a key"
    }
}
