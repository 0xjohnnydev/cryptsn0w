import SwiftUI

struct InstallerNoteView: View {
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Text("NOTE:")
                .bold()
            Text(
                "Back up your device before jailbreaking. The one-shot install pulls SpringBoard and Settings, builds the matched Cryptex, and does not require a reboot."
            )
            .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}
