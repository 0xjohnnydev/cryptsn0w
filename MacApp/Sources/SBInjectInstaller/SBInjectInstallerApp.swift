import SwiftUI

@main
struct SBInjectInstallerApp: App {
    @State private var model = InstallerModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .frame(
                    minWidth: AppTheme.minimumWidth,
                    minHeight: AppTheme.minimumHeight
                )
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) { }
        }
    }
}
