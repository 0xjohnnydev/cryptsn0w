import SwiftUI

struct ManageView: View {
    @Bindable var model: InstallerModel

    private var state: JailbreakState { model.jailbreakState ?? JailbreakState() }

    var body: some View {
        VStack(alignment: .leading, spacing: AppTheme.spacing) {
            header

            HStack(alignment: .top, spacing: 18) {
                lanes
                    .frame(width: 244, alignment: .leading)
                Divider().overlay(AppTheme.strongDivider)
                applications
            }

            AppDropZoneView(model: model)
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("MANAGE")
                    .font(AppTheme.labelFont)
                    .tracking(0.8)
                    .foregroundStyle(AppTheme.mutedInk)
                Text(model.isWorking ? model.manageDetail : state.summary)
                    .font(AppTheme.controlFont)
                    .foregroundStyle(
                        state.isHealthy || model.isWorking
                            ? AppTheme.softInk
                            : AppTheme.failure
                    )
                    .lineLimit(1)
            }
            Spacer()
            if model.isWorking {
                ProgressView()
                    .controlSize(.small)
                    .padding(.trailing, 6)
            }
            Button("Done", action: model.exitManageMode)
                .buttonStyle(CryptexSecondaryButtonStyle())
                .disabled(model.isWorking)
        }
    }

    private var lanes: some View {
        VStack(alignment: .leading, spacing: AppTheme.compactSpacing) {
            toggle(
                "Custom SpringBoard",
                detail: state.springBoardRedirectEnabled ? "injected" : "stock",
                isOn: state.springBoardRedirectEnabled,
                action: model.setSpringBoardRedirect
            )
            toggle(
                "Settings redirect",
                detail: state.preferencesEnabled ? "injected" : "stock",
                isOn: state.preferencesEnabled,
                action: model.setPreferencesRedirect
            )
            toggle(
                "Safe mode",
                detail: state.safeModeActive ? "tweaks off" : "tweaks on",
                isOn: state.safeModeActive,
                action: model.setSafeMode
            )

            Divider().overlay(AppTheme.strongDivider).padding(.vertical, 2)

            HStack(spacing: AppTheme.compactSpacing) {
                Button("Respring", action: model.respring)
                    .buttonStyle(CryptexSecondaryButtonStyle())
                Button("Clear Crash", action: model.clearCrashMarkers)
                    .buttonStyle(CryptexSecondaryButtonStyle())
            }
            .disabled(model.isWorking)

            if state.springBoardCrashTripped || state.preferencesCrashTripped {
                Text("A crash loop disabled a lane; it stays off every boot until cleared.")
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.failure)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var applications: some View {
        VStack(alignment: .leading, spacing: AppTheme.tightSpacing) {
            Text("APPLICATIONS")
                .font(AppTheme.labelFont)
                .tracking(0.8)
                .foregroundStyle(AppTheme.mutedInk)

            if model.managedApps.isEmpty {
                Text("No managed applications installed.")
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.faintInk)
                    .padding(.top, 2)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(model.managedApps) { app in
                            row(app)
                        }
                    }
                }
                .frame(maxHeight: 118)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func row(_ app: ManagedApp) -> some View {
        HStack(spacing: AppTheme.compactSpacing) {
            Circle()
                .fill(app.isPrepared ? AppTheme.success : AppTheme.faintInk)
                .frame(width: 6, height: 6)
            VStack(alignment: .leading, spacing: 0) {
                Text(app.name)
                    .font(AppTheme.controlFont)
                    .foregroundStyle(AppTheme.ink)
                    .lineLimit(1)
                Text(app.identifier)
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.faintInk)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            Button("Remove") { model.uninstall(app) }
                .buttonStyle(CryptexSecondaryButtonStyle(size: .compact))
                .disabled(model.isWorking)
        }
        .padding(.vertical, 2)
    }

    private func toggle(
        _ title: String,
        detail: String,
        isOn: Bool,
        action: @escaping @MainActor @Sendable (Bool) -> Void
    ) -> some View {
        HStack(spacing: AppTheme.compactSpacing) {
            VStack(alignment: .leading, spacing: 0) {
                Text(title)
                    .font(AppTheme.controlFont)
                    .foregroundStyle(AppTheme.ink)
                Text(detail)
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.faintInk)
            }
            Spacer(minLength: 4)
            Toggle(
                "",
                isOn: Binding(
                    get: { isOn },
                    set: { newValue in Task { @MainActor in action(newValue) } }
                )
            )
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.mini)
            .disabled(model.isWorking)
        }
    }
}
