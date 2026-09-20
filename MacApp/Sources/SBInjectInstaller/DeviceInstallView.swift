import SwiftUI

struct DeviceInstallView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        VStack(spacing: 12) {
            Text("Connect your device and click Jailbreak to begin.")
                .font(.body)
                .multilineTextAlignment(.center)

            HStack(spacing: 10) {
                Picker(
                    "Connected device",
                    selection: $model.selectedDeviceIdentifier
                ) {
                    if model.devices.isEmpty {
                        Text("No connected device")
                            .tag(String?.none)
                    }
                    ForEach(model.devices) { device in
                        Text(device.pickerTitle)
                            .tag(Optional(device.id))
                    }
                }
                .labelsHidden()
                .frame(maxWidth: .infinity)
                .disabled(model.state == .running || model.isDiscoveringDevices)
                .accessibilityLabel("Connected device")
                .onChange(of: model.selectedDeviceIdentifier) {
                    model.updateSSHShellAvailability()
                }

                Button(
                    "Refresh Devices",
                    systemImage: "arrow.clockwise",
                    action: model.requestDeviceRefresh
                )
                .labelStyle(.iconOnly)
                .frame(minWidth: 32, minHeight: 32)
                .disabled(model.state == .running || model.isDiscoveringDevices)
                .help("Refresh connected devices")

                Button(model.actionTitle, action: model.startInstall)
                    .buttonStyle(CryptexPrimaryButtonStyle())
                    .disabled(!model.canStart)
                    .accessibilityInputLabels(["Jailbreak", "Install"])
            }

            Toggle(
                "Enable root SSH access for this Mac",
                isOn: $model.enableHostSSH
            )
            .toggleStyle(.checkbox)
            .disabled(model.state == .running)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityHint(
                "When enabled, the installer keeps a device-specific key so the SSH Shell menu can connect as root."
            )
        }
    }
}
