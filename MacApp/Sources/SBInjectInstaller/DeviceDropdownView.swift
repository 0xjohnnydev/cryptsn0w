import SwiftUI

struct DeviceDropdownView: View {
    @Bindable var model: InstallerModel
    @Binding var isPresented: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("CONNECTED DEVICES")
                    .font(AppTheme.labelFont)
                    .tracking(0.8)
                    .foregroundStyle(AppTheme.mutedInk)
                Spacer()
                Button("Close", systemImage: "xmark", action: dismiss)
                    .labelStyle(.iconOnly)
                    .buttonStyle(.plain)
                    .keyboardShortcut(.cancelAction)
                    .help("Close device selection")
            }

            if model.devices.isEmpty {
                VStack(alignment: .leading, spacing: 5) {
                    Text(
                        model.isDiscoveringDevices ? "Looking for devices…" : "No devices connected"
                    )
                    .font(AppTheme.controlFont)
                    Text("Connect your iPhone, unlock it, and trust this Mac.")
                        .font(AppTheme.detailFont)
                        .foregroundStyle(AppTheme.mutedInk)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 8)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(model.devices) { device in
                            DeviceDropdownRow(
                                device: device,
                                isSelected: model.selectedDeviceIdentifier == device.id,
                                selection: $model.selectedDeviceIdentifier,
                                isPresented: $isPresented
                            )
                        }
                    }
                }
                .frame(height: min(CGFloat(model.devices.count) * 54, 216))
            }

            Button(
                "Refresh devices", systemImage: "arrow.clockwise",
                action: model.requestDeviceRefresh
            )
            .font(AppTheme.detailFont)
            .buttonStyle(.plain)
            .foregroundStyle(AppTheme.accent)
            .disabled(model.isDiscoveringDevices || model.state == .running)
        }
        .padding(18)
        .frame(width: 320)
        .background(AppTheme.paperHighlight)
        .foregroundStyle(AppTheme.ink)
    }

    private func dismiss() {
        isPresented = false
    }
}
