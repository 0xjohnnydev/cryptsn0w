import SwiftUI

struct PanguBrushStrokeShape: Shape {
    func path(in rect: CGRect) -> Path {
        let width = rect.width
        let height = rect.height
        let minX = rect.minX
        let minY = rect.minY

        var path = Path()
        path.move(to: CGPoint(x: minX + width * 0.01, y: minY + height * 0.47))
        path.addCurve(
            to: CGPoint(x: minX + width * 0.10, y: minY + height * 0.25),
            control1: CGPoint(x: minX + width * 0.03, y: minY + height * 0.31),
            control2: CGPoint(x: minX + width * 0.06, y: minY + height * 0.20)
        )
        path.addCurve(
            to: CGPoint(x: minX + width * 0.57, y: minY + height * 0.20),
            control1: CGPoint(x: minX + width * 0.25, y: minY + height * 0.12),
            control2: CGPoint(x: minX + width * 0.44, y: minY + height * 0.29)
        )
        path.addCurve(
            to: CGPoint(x: minX + width * 0.97, y: minY + height * 0.39),
            control1: CGPoint(x: minX + width * 0.72, y: minY + height * 0.12),
            control2: CGPoint(x: minX + width * 0.88, y: minY + height * 0.33)
        )
        path.addLine(to: CGPoint(x: minX + width, y: minY + height * 0.49))
        path.addLine(to: CGPoint(x: minX + width * 0.96, y: minY + height * 0.54))
        path.addLine(to: CGPoint(x: minX + width, y: minY + height * 0.61))
        path.addLine(to: CGPoint(x: minX + width * 0.94, y: minY + height * 0.60))
        path.addCurve(
            to: CGPoint(x: minX + width * 0.52, y: minY + height * 0.77),
            control1: CGPoint(x: minX + width * 0.82, y: minY + height * 0.70),
            control2: CGPoint(x: minX + width * 0.67, y: minY + height * 0.65)
        )
        path.addCurve(
            to: CGPoint(x: minX + width * 0.08, y: minY + height * 0.72),
            control1: CGPoint(x: minX + width * 0.36, y: minY + height * 0.86),
            control2: CGPoint(x: minX + width * 0.18, y: minY + height * 0.67)
        )
        path.addLine(to: CGPoint(x: minX, y: minY + height * 0.58))
        path.addLine(to: CGPoint(x: minX + width * 0.04, y: minY + height * 0.53))
        path.closeSubpath()
        return path
    }
}
