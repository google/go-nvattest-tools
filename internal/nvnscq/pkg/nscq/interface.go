package nscq

// Interface is an interface for the NSCQ handler.
type Interface interface {
	Init() Return
	Shutdown() Return
	SessionCreate(uint32) (*Session, Return)
	SessionDestroy(*Session) Return
	SwitchPCIEMode(session *Session, uuid string) (int8, Return)
	SwitchDeviceUUIDs(session *Session) ([]string, Return)
	SwitchArchitecture(session *Session) (int8, Return)
	SwitchAttestationReport(session *Session, nonce [32]uint8, uuid string) ([]uint8, Return)
	SwitchAttestationCertificateChain(session *Session, uuid string) ([]uint8, Return)
}
