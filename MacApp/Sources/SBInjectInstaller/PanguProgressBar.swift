import SwiftUI

struct PanguProgressBar: View {
    let progress: Double
    let state: InstallState

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Canvas { context, size in
            let stroke = brushStroke(in: size)
            context.fill(stroke, with: .color(AppTheme.progressTrack))

            guard normalizedProgress > 0 else { return }
            let filledWidth = size.width * normalizedProgress
            let filledStroke = brushStroke(
                in: CGSize(width: filledWidth, height: size.height)
            )
            context.fill(
                filledStroke,
                with: .linearGradient(
                    Gradient(colors: [progressColor.opacity(0.78), progressColor]),
                    startPoint: .zero,
                    endPoint: CGPoint(x: filledWidth, y: size.height)
                )
            )
        }
        .frame(maxWidth: .infinity, minHeight: 28, maxHeight: 28)
        .animation(
            reduceMotion ? nil : .easeInOut(duration: 0.38),
            value: normalizedProgress
        )
        .accessibilityElement()
        .accessibilityLabel("Jailbreak progress")
        .accessibilityValue(progress.formatted(.percent.precision(.fractionLength(0))))
    }

    private var normalizedProgress: Double {
        min(max(progress, 0), 1)
    }

    private var progressColor: Color {
        switch state {
        case .idle, .running: AppTheme.accent
        case .complete: AppTheme.success
        case .failed: AppTheme.failure
        }
    }

    private func brushStroke(in size: CGSize) -> Path {
        let width = size.width
        let height = size.height
        var path = Path()
        path.move(to: CGPoint(x: width * 0.01, y: height * 0.47))
        path.addCurve(
            to: CGPoint(x: width * 0.10, y: height * 0.25),
            control1: CGPoint(x: width * 0.03, y: height * 0.31),
            control2: CGPoint(x: width * 0.06, y: height * 0.20)
        )
        path.addCurve(
            to: CGPoint(x: width * 0.57, y: height * 0.20),
            control1: CGPoint(x: width * 0.25, y: height * 0.12),
            control2: CGPoint(x: width * 0.44, y: height * 0.29)
        )
        path.addCurve(
            to: CGPoint(x: width * 0.97, y: height * 0.39),
            control1: CGPoint(x: width * 0.72, y: height * 0.12),
            control2: CGPoint(x: width * 0.88, y: height * 0.33)
        )
        path.addLine(to: CGPoint(x: width, y: height * 0.50))
        path.addLine(to: CGPoint(x: width * 0.95, y: height * 0.56))
        path.addCurve(
            to: CGPoint(x: width * 0.52, y: height * 0.77),
            control1: CGPoint(x: width * 0.82, y: height * 0.70),
            control2: CGPoint(x: width * 0.67, y: height * 0.65)
        )
        path.addCurve(
            to: CGPoint(x: width * 0.08, y: height * 0.72),
            control1: CGPoint(x: width * 0.36, y: height * 0.86),
            control2: CGPoint(x: width * 0.18, y: height * 0.67)
        )
        path.addLine(to: CGPoint(x: 0, y: height * 0.55))
        path.closeSubpath()
        return path
    }
}
