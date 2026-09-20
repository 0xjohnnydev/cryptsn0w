import SwiftUI

struct BrandFooterView: View {
    private static let sourceURL: URL = {
        guard let url = URL(
            string: "https://github.com/0xjohnnydev/untitled"
        ) else {
            fatalError("The CryptexSn0w source URL is invalid")
        }
        return url
    }()

    var body: some View {
        HStack(spacing: 14) {
            Image(nsImage: LogoResource.image)
                .resizable()
                .scaledToFit()
                .frame(width: 76, height: 76)
                .accessibilityLabel("Running pineapple CryptexSn0w logo")

            VStack(alignment: .leading, spacing: 5) {
                Text("By 0xJohnny, Varik, and @GenericCoding")
                Text("SBInject by Htrowii")
                Text("Advice from Jake James")
                Link("Project source", destination: Self.sourceURL)
            }
            .font(.callout)
            .foregroundStyle(AppTheme.ink)

            Spacer()

            VStack(spacing: 3) {
                Image(systemName: "snowflake")
                    .font(.system(.largeTitle, design: .rounded))
                    .foregroundStyle(AppTheme.accent)
                Text("SBInject")
                    .font(.callout)
                    .foregroundStyle(AppTheme.mutedInk)
            }
            .accessibilityElement(children: .combine)
        }
        .padding(.top, 10)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(AppTheme.divider)
                .frame(height: 1)
        }
    }
}
