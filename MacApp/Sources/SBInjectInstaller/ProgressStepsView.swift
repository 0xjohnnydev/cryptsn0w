import SwiftUI

struct ProgressStepsView: View {
    let currentStep: InstallStep
    let installState: InstallState

    var body: some View {
        VStack(alignment: .leading, spacing: AppTheme.compactSpacing) {
            Text("Progress")
                .font(.headline)
            ForEach(InstallStep.allCases) { step in
                InstallStepRow(
                    step: step,
                    currentStep: currentStep,
                    installState: installState
                )
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(width: 250)
        .frame(maxHeight: .infinity, alignment: .topLeading)
        .background(AppTheme.panel)
        .clipShape(.rect(cornerRadius: AppTheme.cornerRadius))
    }
}
