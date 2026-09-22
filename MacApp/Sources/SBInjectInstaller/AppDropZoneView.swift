import SwiftUI
import UniformTypeIdentifiers

struct AppDropZoneView: View {
    @Bindable var model: InstallerModel
    @State private var isTargeted = false

    var body: some View {
        VStack(spacing: AppTheme.tightSpacing) {
            Image(systemName: isTargeted ? "square.and.arrow.down.fill" : "square.and.arrow.down")
                .font(.system(size: 18, weight: .light))
                .foregroundStyle(isTargeted ? AppTheme.accent : AppTheme.faintInk)
            Text(isTargeted ? "Release to install" : "Drop an .ipa or .app here")
                .font(AppTheme.controlFont)
                .foregroundStyle(isTargeted ? AppTheme.accent : AppTheme.mutedInk)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(isTargeted ? AppTheme.accent.opacity(0.07) : Color.black.opacity(0.02))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(
                    isTargeted ? AppTheme.accent : AppTheme.strongDivider,
                    style: StrokeStyle(lineWidth: 1, dash: [4, 3])
                )
        )
        .animation(.easeOut(duration: 0.12), value: isTargeted)
        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
            guard !model.isWorking, let provider = providers.first else {
                return false
            }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in
                    model.installDropped(url)
                }
            }
            return true
        }
        .disabled(model.isWorking)
        .opacity(model.isWorking ? 0.5 : 1)
    }
}
