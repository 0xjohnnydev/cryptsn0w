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
}
