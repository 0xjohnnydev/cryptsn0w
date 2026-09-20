import SwiftUI

struct InstallerHeaderView: View {
    let statusTitle: String

    var body: some View {
        HStack(spacing: AppTheme.spacing) {
            Image(nsImage: LogoResource.image)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 132, maxHeight: 132)
                .accessibilityLabel("Running pineapple jailbreak logo")
            VStack(alignment: .leading, spacing: AppTheme.compactSpacing) {
                Text("SBInject")
                    .font(.largeTitle)
                    .bold()
                Text("Cryptex jailbreak for SpringBoard and Settings")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                Label(statusTitle, systemImage: "iphone.gen3.radiowaves.left.and.right")
                    .font(.headline)
                    .foregroundStyle(AppTheme.accent)
            }
            Spacer()
        }
        .padding()
        .background(AppTheme.panel)
        .clipShape(.rect(cornerRadius: AppTheme.cornerRadius))
        .shadow(radius: 3, y: 2)
    }
}
