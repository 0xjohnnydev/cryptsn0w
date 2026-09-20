import SwiftUI

struct InstallerLogView: View {
    let lines: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: AppTheme.compactSpacing) {
            Label("Installer Log", systemImage: "terminal")
                .font(.headline)
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 3) {
                        if lines.isEmpty {
                            Text("Waiting to start…")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(lines.indices, id: \.self) { index in
                            Text(lines[index])
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .id(index)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(AppTheme.compactSpacing)
                }
                .background(.black.opacity(0.88))
                .foregroundStyle(.white)
                .clipShape(.rect(cornerRadius: AppTheme.cornerRadius / 2))
                .onChange(of: lines.count) { _, newCount in
                    guard newCount > 0 else { return }
                    proxy.scrollTo(newCount - 1, anchor: .bottom)
                }
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppTheme.panel)
        .clipShape(.rect(cornerRadius: AppTheme.cornerRadius))
    }
}
