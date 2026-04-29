// Package mock provides a mock implementation of nscq.Interface.
package mock

import (
	"github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq"
)

var _ nscq.Interface = &Interface{}

// Interface is a mock implementation of nscq.Interface.
type Interface struct {
	InitFunc                              func() nscq.Return
	ShutdownFunc                          func() nscq.Return
	SessionCreateFunc                     func(uint32) (*nscq.Session, nscq.Return)
	SessionDestroyFunc                    func(*nscq.Session) nscq.Return
	SwitchPCIEModeFunc                    func(*nscq.Session, string) (int8, nscq.Return)
	SwitchDeviceUUIDsFunc                 func(*nscq.Session) ([]string, nscq.Return)
	SwitchArchitectureFunc                func(*nscq.Session) (int8, nscq.Return)
	SwitchAttestationReportFunc           func(*nscq.Session, [32]uint8, string) ([]uint8, nscq.Return)
	SwitchAttestationCertificateChainFunc func(*nscq.Session, string) ([]uint8, nscq.Return)
}

// SessionCreate is a mock implementation of nscq.Interface.SessionCreate.
func (mock *Interface) SessionCreate(flags uint32) (*nscq.Session, nscq.Return) {
	if mock.SessionCreateFunc == nil {
		panic("Interface.SessionCreateFunc: method is nil but Interface.SessionCreate was just called")
	}
	return mock.SessionCreateFunc(flags)
}

// SessionDestroy is a mock implementation of nscq.Interface.SessionDestroy.
func (mock *Interface) SessionDestroy(session *nscq.Session) nscq.Return {
	if mock.SessionDestroyFunc == nil {
		panic("Interface.SessionDestroyFunc: method is nil but Interface.SessionDestroy was just called")
	}
	return mock.SessionDestroyFunc(session)
}

// Init is a mock implementation of nscq.Interface.Init.
func (mock *Interface) Init() nscq.Return {
	if mock.InitFunc == nil {
		panic("Interface.InitFunc: method is nil but Interface.Init was just called")
	}
	return mock.InitFunc()
}

// Shutdown is a mock implementation of nscq.Interface.Shutdown.
func (mock *Interface) Shutdown() nscq.Return {
	if mock.ShutdownFunc == nil {
		panic("Interface.ShutdownFunc: method is nil but Interface.Shutdown was just called")
	}
	return mock.ShutdownFunc()
}

// SwitchPCIEMode is a mock implementation of nscq.Interface.SwitchPCIEMode.
func (mock *Interface) SwitchPCIEMode(session *nscq.Session, uuid string) (int8, nscq.Return) {
	if mock.SwitchPCIEModeFunc == nil {
		panic("Interface.SwitchPCIEModeFunc: method is nil but Interface.SwitchPCIEMode was just called")
	}
	return mock.SwitchPCIEModeFunc(session, uuid)
}

// SwitchDeviceUUIDs is a mock implementation of nscq.Interface.SwitchDeviceUUIDs.
func (mock *Interface) SwitchDeviceUUIDs(session *nscq.Session) ([]string, nscq.Return) {
	if mock.SwitchDeviceUUIDsFunc == nil {
		panic("Interface.SwitchDeviceUUIDsFunc: method is nil but Interface.SwitchDeviceUUIDs was just called")
	}
	return mock.SwitchDeviceUUIDsFunc(session)
}

// SwitchArchitecture is a mock implementation of nscq.Interface.SwitchArchitecture.
func (mock *Interface) SwitchArchitecture(session *nscq.Session) (int8, nscq.Return) {
	if mock.SwitchArchitectureFunc == nil {
		panic("Interface.SwitchArchitectureFunc: method is nil but Interface.SwitchArchitecture was just called")
	}
	return mock.SwitchArchitectureFunc(session)
}

// SwitchAttestationReport is a mock implementation of nscq.Interface.SwitchAttestationReport.
func (mock *Interface) SwitchAttestationReport(session *nscq.Session, nonce [32]uint8, uuid string) ([]uint8, nscq.Return) {
	if mock.SwitchAttestationReportFunc == nil {
		panic("Interface.SwitchAttestationReportFunc: method is nil but Interface.SwitchAttestationReport was just called")
	}
	return mock.SwitchAttestationReportFunc(session, nonce, uuid)
}

// SwitchAttestationCertificateChain is a mock implementation of nscq.Interface.SwitchAttestationCertificateChain.
func (mock *Interface) SwitchAttestationCertificateChain(session *nscq.Session, uuid string) ([]uint8, nscq.Return) {
	if mock.SwitchAttestationCertificateChainFunc == nil {
		panic("Interface.SwitchAttestationCertificateChainFunc: method is nil but Interface.SwitchAttestationCertificateChain was just called")
	}
	return mock.SwitchAttestationCertificateChainFunc(session, uuid)
}
