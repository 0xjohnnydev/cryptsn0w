import SwiftUI

struct TitleStripView: View {
    var body: some View {
        HStack {
            Text("CryptexSn0w for iOS")
                .font(.headline)
                .bold()
            Spacer()
            Text("version: 1.0.0")
                .font(.callout)
                .foregroundStyle(AppTheme.mutedInk)
        }
        .padding(.leading, 78)
        .padding(.trailing, 16)
        .frame(height: 38)
        .background(AppTheme.surface)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(AppTheme.divider)
                .frame(height: 1)
        }
        .accessibilityElement(children: .combine)
    }
}
