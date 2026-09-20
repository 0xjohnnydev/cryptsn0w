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
        HStack(spacing: 12) {
            Image(nsImage: LogoResource.image)
                .resizable()
                .scaledToFit()
                .frame(width: 68, height: 68)
                .accessibilityLabel("Running pineapple CryptexSn0w logo")

            VStack(alignment: .leading, spacing: 2) {
                Text("CryptexSn0w")
                    .font(.headline)
                    .bold()
                Text("By 0xJohnny, Varik, and @GenericCoding")
                Text("SBInject by Htrowii · Advice from Jake James")
                    .foregroundStyle(AppTheme.mutedInk)
                Link("Project source", destination: Self.sourceURL)
            }
            .font(.callout)
            .foregroundStyle(AppTheme.ink)

            Spacer(minLength: 12)

            VStack(spacing: 4) {
                ZStack {
                    Circle()
                        .fill(AppTheme.accent)
                    Image(systemName: "snowflake")
                        .font(.title2)
                        .foregroundStyle(.white)
                }
                .frame(width: 42, height: 42)
                Text("SBInject")
                    .font(.callout)
                    .foregroundStyle(AppTheme.mutedInk)
            }
            .accessibilityElement(children: .combine)
        }
        .padding(.top, 12)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(AppTheme.divider)
                .frame(height: 1)
        }
    }
}
