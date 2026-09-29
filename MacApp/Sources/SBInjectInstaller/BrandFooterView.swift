import SwiftUI

struct BrandFooterView: View {
    private static let sourceURL = URL(string: "https://github.com/0xjohnnydev/untitled")!

    var body: some View {
        HStack(spacing: 12) {
            Image(nsImage: LogoResource.image)
                .resizable()
                .scaledToFit()
                .frame(width: 48, height: 48)
                .accessibilityLabel("Running pineapple CryptSn0w logo")

            VStack(alignment: .leading, spacing: 2) {
                Text("CryptSn0w")
                    .font(AppTheme.brandFont)

                Text("By 0xJohnny, Varik & @GenericCoding")
                    .font(AppTheme.detailFont)

                Text("SBInject by Htrowii · Advice from Jake James")
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.mutedInk)
            }
            .foregroundStyle(AppTheme.ink)

            Spacer(minLength: 12)

            Link(destination: Self.sourceURL) {
                Label("Source", systemImage: "arrow.up.right")
                    .font(AppTheme.detailFont)
                    .foregroundStyle(AppTheme.accent)
            }
            .buttonStyle(.plain)
            .help("Open the CryptSn0w project source")
        }
        .padding(.top, 18)
        .background {
            PanguBrushStrokeShape()
                .fill(AppTheme.accent.opacity(0.038))
                .frame(height: 82)
                .rotationEffect(.degrees(-1.5))
                .offset(x: 44, y: 6)
                .accessibilityHidden(true)
        }
        .overlay(alignment: .top) {
            PanguBrushStrokeShape()
                .fill(
                    LinearGradient(
                        colors: [
                            AppTheme.accentBright,
                            AppTheme.accentBright.opacity(0.46),
                            AppTheme.accentBright.opacity(0.06),
                        ],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .frame(height: 16)
                .accessibilityHidden(true)
        }
    }
}
