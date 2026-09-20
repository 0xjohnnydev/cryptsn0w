import SwiftUI

@main
struct CryptexSn0wApp: App {
    @State private var model = InstallerModel()

    var body: some Scene {
        Window("CryptexSn0w", id: "main") {
            ContentView(model: model)
        }
        .defaultSize(
            width: AppTheme.windowWidth,
            height: AppTheme.windowHeight
        )
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Device") {
                Button(
                    "Refresh Devices",
                    systemImage: "arrow.clockwise",
                    action: model.requestDeviceRefresh
                )
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(model.state == .running)

                Button(
                    "Show Install Log",
                    systemImage: "doc.text",
                    action: model.showLog
                )
                .disabled(!model.canShowLog)

                Button(
                    "Choose Repository…",
                    systemImage: "folder",
                    action: model.chooseRepository
                )
                .disabled(model.state == .running)

                Divider()

                Button(
                    "Open SSH Shell…",
                    systemImage: "terminal",
                    action: model.openSSHShell
                )
                .keyboardShortcut("s", modifiers: [.command, .shift])
                .disabled(!model.canOpenSSHShell)
            }
        }
    }
}
