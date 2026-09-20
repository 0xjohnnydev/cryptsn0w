enum InstallStep: Int, CaseIterable, Identifiable, Sendable {
    case connect
    case transferStage
    case copySystemApps
    case buildFinal
    case installFinal
    case verify

    var id: Self { self }

    var title: String {
        switch self {
        case .connect: "Connect to device"
        case .transferStage: "Start secure transfer"
        case .copySystemApps: "Copy SpringBoard & Settings"
        case .buildFinal: "Build SBInject Cryptex"
        case .installFinal: "Install jailbreak"
        case .verify: "Verify Sileo & tweaks"
        }
    }

    var progress: Double {
        switch self {
        case .connect: 0.08
        case .transferStage: 0.24
        case .copySystemApps: 0.43
        case .buildFinal: 0.64
        case .installFinal: 0.82
        case .verify: 0.95
        }
    }
}
