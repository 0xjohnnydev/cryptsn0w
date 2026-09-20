struct FlowSummary: Decodable, Sendable {
    let result: String
    let device: FlowSummaryDevice
    let hostSSHPrivateKey: String?
}
