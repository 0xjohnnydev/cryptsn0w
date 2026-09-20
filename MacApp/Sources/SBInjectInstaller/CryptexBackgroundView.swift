import SwiftUI

struct CryptexBackgroundView: View {
    var body: some View {
        Canvas { context, size in
            context.fill(
                Path(CGRect(origin: .zero, size: size)),
                with: .color(AppTheme.paper)
            )

            var upperWave = Path()
            upperWave.move(to: .zero)
            upperWave.addLine(to: CGPoint(x: size.width, y: 0))
            upperWave.addLine(to: CGPoint(x: size.width, y: 92))
            upperWave.addCurve(
                to: CGPoint(x: 0, y: 70),
                control1: CGPoint(x: size.width * 0.68, y: 42),
                control2: CGPoint(x: size.width * 0.28, y: 112)
            )
            upperWave.closeSubpath()
            context.fill(upperWave, with: .color(.white.opacity(0.72)))

            var lowerWave = Path()
            lowerWave.move(to: CGPoint(x: 0, y: size.height * 0.70))
            lowerWave.addCurve(
                to: CGPoint(x: size.width, y: size.height * 0.62),
                control1: CGPoint(x: size.width * 0.33, y: size.height * 0.57),
                control2: CGPoint(x: size.width * 0.72, y: size.height * 0.82)
            )
            lowerWave.addLine(to: CGPoint(x: size.width, y: size.height))
            lowerWave.addLine(to: CGPoint(x: 0, y: size.height))
            lowerWave.closeSubpath()
            context.fill(lowerWave, with: .color(.white.opacity(0.56)))

            let halo = Path(
                ellipseIn: CGRect(
                    x: size.width * 0.56,
                    y: size.height * 0.38,
                    width: size.width * 0.34,
                    height: size.width * 0.34
                )
            )
            context.fill(halo, with: .color(.gray.opacity(0.035)))
        }
        .accessibilityHidden(true)
    }
}
