import SwiftUI

struct DevicePickerView: View {
    @Bindable var model: InstallerModel
    @State private var isExpanded = false

    var body: some View {
        HStack(spacing: AppTheme.rowSpacing) {
            Image(systemName: "iphone.gen3")
                .font(.system(size: 21))
                .foregroundStyle(AppTheme.accent)
                .frame(width: AppTheme.rowIconWidth)
                .accessibilityHidden(true)

            Button(action: toggleDropdown) {
                HStack(spacing: AppTheme.compactSpacing) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("DEVICE")
                            .font(AppTheme.labelFont)
                            .tracking(0.8)
                            .foregroundStyle(AppTheme.mutedInk)
                        Text(model.selectedDevice?.pickerTitle ?? "Choose a device")
                            .font(AppTheme.controlFont)
                            .foregroundStyle(AppTheme.ink)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.down")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(AppTheme.mutedInk)
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                }
                .frame(maxWidth: .infinity, minHeight: 40, alignment: .leading)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .disabled(model.state == .running || model.isDiscoveringDevices)
            .accessibilityLabel("Choose connected device")
            .accessibilityValue(model.selectedDevice?.pickerTitle ?? "No device selected")
            .popover(isPresented: $isExpanded, arrowEdge: .bottom) {
                DeviceDropdownView(model: model, isPresented: $isExpanded)
            }

            DeviceConnectionBadgeView(
                isDiscovering: model.isDiscoveringDevices,
                isConnected: model.selectedDevice != nil
            )

            Button(
                "Refresh Devices", systemImage: "arrow.clockwise",
                action: model.requestDeviceRefresh
            )
            .labelStyle(.iconOnly)
            .buttonStyle(CryptexIconButtonStyle())
            .disabled(model.state == .running || model.isDiscoveringDevices)
            .help("Refresh connected devices")
        }
        .onChange(of: model.selectedDeviceIdentifier) {
            model.updateSSHShellAvailability()
        }
        .onChange(of: model.state) {
            if model.state == .running { isExpanded = false }
        }
    }

    private func toggleDropdown() {
        isExpanded.toggle()
    }
}
