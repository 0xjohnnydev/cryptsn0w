import SwiftUI

struct ContentView: View {
    @Bindable var model: InstallerModel

    var body: some View {
        VStack(spacing: AppTheme.spacing) {
            InstallerHeaderView(statusTitle: model.statusTitle)
            DeviceOptionsView(model: model)
            HStack(alignment: .top, spacing: AppTheme.spacing) {
                ProgressStepsView(
                    currentStep: model.currentStep,
                    installState: model.state
                )
                InstallerLogView(lines: model.logLines)
            }
            InstallerActionView(model: model)
        }
        .padding()
        .background {
            LinearGradient(
                colors: [
                    Color(red: 0.87, green: 0.90, blue: 0.94),
                    Color(red: 0.65, green: 0.72, blue: 0.80),
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()
        }
        .alert("Installation Failed", isPresented: $model.isShowingError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(model.errorMessage)
        }
    }
}
