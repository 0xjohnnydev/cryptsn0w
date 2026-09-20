import SwiftUI

struct TitleStripView: View {
    var body: some View {
        HStack {
            Text("CryptexSn0w")
                .font(.headline)
                .bold()
            Spacer()
            Text("version: 1.0.0")
                .font(.callout)
                .foregroundStyle(AppTheme.mutedInk)
        }
        .padding(.leading, 78)
        .padding(.trailing, 14)
        .frame(height: 36)
        .background(.white.opacity(0.48))
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(AppTheme.divider)
                .frame(height: 1)
        }
        .accessibilityElement(children: .combine)
    }
}
