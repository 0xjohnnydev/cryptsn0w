import SwiftUI

struct InstallStepRow: View {
    let step: InstallStep
    let currentStep: InstallStep
    let installState: InstallState

    private var isComplete: Bool {
        installState == .complete || step.rawValue < currentStep.rawValue
    }

    private var isActive: Bool {
        installState == .running && step == currentStep
    }

    var body: some View {
        Label {
            Text(step.title)
                .foregroundStyle(isActive ? .primary : .secondary)
        } icon: {
            Image(
                systemName: isComplete
                    ? "checkmark.circle.fill"
                    : isActive ? "circle.inset.filled" : "circle"
            )
            .foregroundStyle(
                isComplete ? .green : isActive ? AppTheme.accent : .secondary
            )
        }
        .font(isActive ? .headline : .body)
        .accessibilityValue(
            isComplete ? "Complete" : isActive ? "In progress" : "Waiting"
        )
    }
}
