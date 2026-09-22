import Foundation

struct JailbreakState: Sendable, Equatable {
    var jailbreakRoot = ""
    var springBoardDetail = ""
    var springBoardRedirectEnabled = false
    var springBoardCrashTripped = false
    var preferencesEnabled = false
    var preferencesCrashTripped = false
    var safeModeActive = false
    var amfidHookReady = false
    var amfidInjectionEnabled = false
    var launchdHookReady = false

    var isHealthy: Bool {
        springBoardRedirectEnabled && amfidHookReady && launchdHookReady
            && !springBoardCrashTripped && !preferencesCrashTripped
    }

    var summary: String {
        if springBoardCrashTripped || preferencesCrashTripped {
            "A crash loop disabled a lane. Clear it to re-arm."
        } else if safeModeActive {
            "Safe mode: jailbroken SpringBoard, tweaks not loaded."
        } else if springBoardRedirectEnabled {
            "SpringBoard redirect active, tweaks loading."
        } else {
            "Stock SpringBoard. The redirect is turned off."
        }
    }

    static func parse(_ output: String) -> JailbreakState {
        var state = JailbreakState()
        for line in output.split(separator: "\n") {
            let parts = line.split(
                separator: " ",
                maxSplits: 1,
                omittingEmptySubsequences: true
            )
            guard parts.count == 2 else { continue }
            let key = String(parts[0])
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "jailbreakRoot": state.jailbreakRoot = value
            case "springBoard": state.springBoardDetail = value
            case "springBoardRedirect":
                state.springBoardRedirectEnabled = value == "enabled"
            case "springBoardCrash":
                state.springBoardCrashTripped = value == "TRIPPED"
            case "preferences": state.preferencesEnabled = value == "enabled"
            case "preferencesCrash":
                state.preferencesCrashTripped = value == "TRIPPED"
            case "tweakSafeMode": state.safeModeActive = value == "active"
            case "amfidHook": state.amfidHookReady = value == "ready"
            case "amfidInjection":
                state.amfidInjectionEnabled = value == "enabled"
            case "launchdHook": state.launchdHookReady = value == "ready"
            default: continue
            }
        }
        return state
    }
}
