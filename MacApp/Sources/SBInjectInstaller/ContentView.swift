import SwiftUI

struct ContentView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        ZStack {
            CryptexBackgroundView()
            VStack(spacing: 12) {
                DeviceInstallView(model: model)
                InstallStatusView(model: model)
                Spacer(minLength: 0)
                BrandFooterView()
            }
            .padding(.horizontal, AppTheme.contentHorizontalPadding)
            .padding(.top, AppTheme.contentTopPadding)
            .padding(.bottom, AppTheme.contentBottomPadding)
        }
        .frame(width: AppTheme.windowWidth, height: AppTheme.windowHeight)
        .foregroundStyle(AppTheme.ink)
        .tint(AppTheme.accent)
        .font(AppTheme.controlFont)
        .preferredColorScheme(.light)
        .task {
            await model.refreshDevices()
        }
        .alert(model.errorTitle, isPresented: $model.isShowingError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage)
        }
    }
}
