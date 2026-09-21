import SwiftUI

struct DeviceDropdownRow: View {
    let device: ConnectedDevice
    let isSelected: Bool
    @Binding var selection: String?
    @Binding var isPresented: Bool
    @State private var isHovered = false

    var body: some View {
        Button(action: selectDevice) {
            HStack(spacing: AppTheme.rowSpacing) {
                Image(systemName: "iphone.gen3")
                    .foregroundStyle(AppTheme.accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(device.pickerTitle)
                        .font(AppTheme.controlFont)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(
                        device.systemVersion == "unknown"
                            ? device.transport : "iOS \(device.systemVersion) · \(device.transport)"
                    )
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.mutedInk)
                }
                Spacer(minLength: 4)
                Image(systemName: "checkmark")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(AppTheme.accent)
                    .opacity(isSelected ? 1 : 0)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 8)
            .frame(height: 52)
            .contentShape(.rect)
            .background {
                PanguBrushStrokeShape()
                    .fill(AppTheme.accent.opacity(isHovered ? 0.12 : isSelected ? 0.06 : 0))
                    .allowsHitTesting(false)
            }
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private func selectDevice() {
        selection = device.id
        isPresented = false
    }
}
