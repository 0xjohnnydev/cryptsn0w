import SwiftUI

struct CryptexBackgroundView: View {
    var body: some View {
        AppTheme.backgroundGradient
            .overlay {
                ZStack {
                    Circle()
                        .fill(AppTheme.accent.opacity(0.10))
                        .frame(width: 330, height: 330)
                        .blur(radius: 80)
                        .offset(x: 290, y: -230)

                    Circle()
                        .fill(.white.opacity(0.90))
                        .frame(width: 300, height: 300)
                        .blur(radius: 72)
                        .offset(x: -310, y: 245)

                    Canvas { context, size in
                        for index in 0..<20 {
                            let fraction = CGFloat(index) / 19
                            let y = size.height * fraction
                            var fiber = Path()
                            fiber.move(to: CGPoint(x: -20, y: y))
                            fiber.addCurve(
                                to: CGPoint(x: size.width + 20, y: y + 2),
                                control1: CGPoint(x: size.width * 0.30, y: y - 4),
                                control2: CGPoint(x: size.width * 0.72, y: y + 5)
                            )
                            context.stroke(
                                fiber,
                                with: .color(
                                    AppTheme.ink.opacity(index.isMultiple(of: 3) ? 0.018 : 0.010)),
                                lineWidth: 0.6
                            )
                        }
                    }

                    PanguBrushStrokeShape()
                        .fill(.white.opacity(0.46))
                        .frame(width: 820, height: 154)
                        .rotationEffect(.degrees(-4))
                        .offset(x: -34, y: -112)

                    PanguBrushStrokeShape()
                        .fill(AppTheme.accentGradient)
                        .frame(width: 840, height: 164)
                        .rotationEffect(.degrees(-7))
                        .opacity(0.052)
                        .offset(x: 168, y: 116)

                    PanguBrushStrokeShape()
                        .fill(AppTheme.ink)
                        .frame(width: 730, height: 112)
                        .rotationEffect(.degrees(5))
                        .opacity(0.022)
                        .offset(x: -205, y: 252)

                    PanguBrushStrokeShape()
                        .fill(AppTheme.accent)
                        .frame(width: 560, height: 74)
                        .rotationEffect(.degrees(2))
                        .opacity(0.030)
                        .offset(x: -300, y: -178)
                }
            }
            .clipped()
            .accessibilityHidden(true)
    }
}
