import SwiftUI

/// Hand-painted edges with a dense center to keep the action label readable.
struct JailbreakBrushView: View {
    let isEnabled: Bool
    let isPressed: Bool

    var body: some View {
        Canvas { context, size in
            let ink = isEnabled ? AppTheme.ink : AppTheme.mutedInk.opacity(0.58)
            func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: size.width * x, y: size.height * y)
            }

            var stroke = Path()
            stroke.move(to: point(0.045, 0.26))
            stroke.addCurve(
                to: point(0.48, 0.15), control1: point(0.17, 0.10), control2: point(0.31, 0.17))
            stroke.addCurve(
                to: point(0.94, 0.12), control1: point(0.67, 0.12), control2: point(0.82, 0.20))
            stroke.addLine(to: point(0.90, 0.25))
            stroke.addLine(to: point(0.98, 0.22))
            stroke.addLine(to: point(0.94, 0.36))
            stroke.addLine(to: point(0.995, 0.38))
            stroke.addLine(to: point(0.95, 0.48))
            stroke.addLine(to: point(0.98, 0.58))
            stroke.addLine(to: point(0.92, 0.64))
            stroke.addLine(to: point(0.96, 0.73))
            stroke.addCurve(
                to: point(0.51, 0.86), control1: point(0.84, 0.77), control2: point(0.69, 0.91))
            stroke.addCurve(
                to: point(0.035, 0.87), control1: point(0.29, 0.78), control2: point(0.17, 0.90))
            stroke.addLine(to: point(0.065, 0.73))
            stroke.addLine(to: point(0.015, 0.68))
            stroke.addLine(to: point(0.06, 0.55))
            stroke.addLine(to: point(0.025, 0.46))
            stroke.addLine(to: point(0.075, 0.34))
            stroke.closeSubpath()
            context.fill(
                stroke,
                with: .linearGradient(
                    Gradient(colors: [ink.opacity(0.89), ink, ink.opacity(0.94)]),
                    startPoint: .zero,
                    endPoint: point(1, 1)
                )
            )

            // Short, uneven bristles stay clear of the label in the center.
            for index in 0..<13 {
                let fraction = CGFloat(index) / 12
                let y = 0.24 + fraction * 0.53
                let inset = CGFloat((index * 7) % 9) / 100
                var tip = Path()
                tip.move(to: point(0.80 + inset, y))
                tip.addLine(to: point(0.995 - inset * 0.36, y - 0.04))
                context.stroke(
                    tip, with: .color(ink.opacity(0.64)),
                    lineWidth: index.isMultiple(of: 3) ? 1.1 : 0.6)

                var grain = Path()
                grain.move(to: point(0.035 + inset * 0.4, y + 0.035))
                grain.addLine(to: point(0.12 + inset, y))
                context.stroke(grain, with: .color(AppTheme.paper.opacity(0.22)), lineWidth: 0.5)
            }
        }
        .opacity(isPressed ? 0.82 : 1)
        .accessibilityHidden(true)
        .allowsHitTesting(false)
    }
}
