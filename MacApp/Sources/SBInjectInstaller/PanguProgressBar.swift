import SwiftUI

struct PanguProgressBar: View {
    let progress: Double
    let state: InstallState

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Canvas { context, size in
            let bounds = CGRect(origin: .zero, size: size)
            let stroke = PanguBrushStrokeShape().path(in: bounds)
            context.fill(
                stroke,
                with: .linearGradient(
                    Gradient(colors: [
                        AppTheme.progressTrack.opacity(0.72),
                        AppTheme.progressTrack,
                    ]),
                    startPoint: .zero,
                    endPoint: CGPoint(x: size.width, y: size.height)
                )
            )
            context.stroke(stroke, with: .color(.white.opacity(0.42)), lineWidth: 0.7)

            guard normalizedProgress > 0 else { return }
            let filledWidth = size.width * normalizedProgress
            let filledStroke = PanguBrushStrokeShape().path(
                in: CGRect(x: 0, y: 0, width: filledWidth, height: size.height)
            )
            context.fill(
                filledStroke,
                with: .linearGradient(
                    Gradient(colors: [
                        progressColor.opacity(0.72),
                        progressColor,
                        progressColor.opacity(0.90),
                    ]),
                    startPoint: .zero,
                    endPoint: CGPoint(x: filledWidth, y: size.height)
                )
            )
            context.fill(
                filledStroke,
                with: .linearGradient(
                    Gradient(colors: [.white.opacity(0.34), .clear, .clear]),
                    startPoint: CGPoint(x: 0, y: 0),
                    endPoint: CGPoint(x: 0, y: size.height)
                )
            )
        }
        .frame(maxWidth: .infinity, minHeight: 30, maxHeight: 30)
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
        .black
    }
}
