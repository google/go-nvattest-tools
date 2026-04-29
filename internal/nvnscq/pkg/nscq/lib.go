package nscq

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"sync"

	"github.com/NVIDIA/go-nvml/pkg/dl"
)

import "C"

// Default values for the NSCQ library.
const (
	defaultNscqLibraryName      = "libnvidia-nscq.so"
	defaultNscqLibraryLoadFlags = dl.RTLD_LAZY | dl.RTLD_GLOBAL
)

// Bindings to the C functions.
var (
	Init           = libnscq.Init
	Shutdown       = libnscq.Shutdown
	SessionCreate  = libnscq.SessionCreate
	SessionDestroy = libnscq.SessionDestroy
)

var errLibraryNotLoaded = errors.New("library not loaded")

// dynamicLibrary is an interface for abstracting the underlying library.
type dynamicLibrary interface {
	Lookup(string) error
	Open() error
	Close() error
}

type nscqBindings interface {
	sessionCreate(uint32) (*Session, Return)
	sessionDestroy(*Session)
	setInput(*Session, uint32, string, uint32) Return
	sessionPathObservePCIEMode(*Session, string, *library) Return
	sessionPathObserveUUID(*Session, string, *library) Return
	sessionPathObserveArchitecture(*Session, string, *library) Return
	sessionPathObserveAttestationReport(*Session, string, *library) Return
	sessionPathObserveAttestationCertificateChain(*Session, string, *library) Return
}

type defaultNSCQBindings struct{}

func (b *defaultNSCQBindings) sessionCreate(flags uint32) (*Session, Return) {
	return sessionCreate(flags)
}

func (b *defaultNSCQBindings) sessionDestroy(session *Session) {
	sessionDestroy(session)
}

func (b *defaultNSCQBindings) setInput(session *Session, nonce uint32, uuid string, reportSize uint32) Return {
	return setInput(session, nonce, uuid, reportSize)
}

func (b *defaultNSCQBindings) sessionPathObservePCIEMode(session *Session, path string, l *library) Return {
	return sessionPathObservePCIEModeImpl(session, path, l)
}

func (b *defaultNSCQBindings) sessionPathObserveUUID(session *Session, path string, l *library) Return {
	return sessionPathObserveUUIDImpl(session, path, l)
}

func (b *defaultNSCQBindings) sessionPathObserveArchitecture(session *Session, path string, l *library) Return {
	return sessionPathObserveArchitectureImpl(session, path, l)
}

func (b *defaultNSCQBindings) sessionPathObserveAttestationReport(session *Session, path string, l *library) Return {
	return sessionPathObserveAttestationReportImpl(session, path, l)
}

func (b *defaultNSCQBindings) sessionPathObserveAttestationCertificateChain(session *Session, path string, l *library) Return {
	return sessionPathObserveAttestationCertificateChainImpl(session, path, l)
}

// library represents an nscq library.
// This includes a reference to the underlying DynamicLibrary
type library struct {
	sync.Mutex
	path     string
	refcount refcount
	dl       dynamicLibrary

	// Fields for storing callback results.
	lastUUIDs                []string
	lastRC                   Return
	lastStatus               int8
	lastArch                 int8
	lastAttestationReport    []uint8
	lastAttestationCertChain []uint8

	isInitialized bool
	handle        uintptr

	nscqBindings nscqBindings
}

var _ Interface = (*library)(nil)

var libnscq = newLibrary()

// New returns a new NSCQ library instance. It allows configuration of the library path and load flags via `LibraryOption` arguments.
// Default values are used if no options are provided. **Crucially**, when providing custom options, the caller is responsible for
// ensuring the specified library path is valid and points to the correct library. Using `LookupSymbol` with a library other than
// `libnvidia-nscq.so` will cause it to fail.
func New(opts ...LibraryOption) Interface {
	return newLibrary(opts...)
}

func newLibrary(opts ...LibraryOption) *library {
	l := &library{
		nscqBindings: &defaultNSCQBindings{},
	}
	l.init(opts...)
	return l
}

func (l *library) init(opts ...LibraryOption) {
	o := libraryOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	if o.path == "" {
		o.path = defaultNscqLibraryName
	}
	if o.flags == 0 {
		o.flags = defaultNscqLibraryLoadFlags
	}

	l.path = o.path
	l.dl = dl.New(o.path, o.flags)
}

func (l *library) Extensions() ExtendedInterface {
	return l
}

// LookupSymbol checks whether the specified library symbol exists in the library.
// Note that this requires that the library be loaded.
func (l *library) LookupSymbol(name string) error {
	if l == nil || l.refcount == 0 {
		return errLibraryNotLoaded
	}
	return l.dl.Lookup(name)
}

// load initializes the library.
// Multiple calls to an already loaded library will return without error.
func (l *library) load() (rerr error) {
	l.Lock()
	defer l.Unlock()

	defer func() { l.refcount.IncOnNoError(rerr) }()
	if l.refcount > 0 {
		return nil
	}

	if err := l.dl.Open(); err != nil {
		return fmt.Errorf("error opening %s: %w", l.path, err)
	}

	return nil
}

// close the underlying library and ensure that the global pointer to the
// library is set to nil to ensure that subsequent calls to open will reinitialize it.
// Multiple calls to an already closed nscq library will return without error.
func (l *library) close() (rerr error) {
	l.Lock()
	defer l.Unlock()

	defer func() { l.refcount.DecOnNoError(rerr) }()
	if l.refcount != 1 {
		return nil
	}

	if err := l.dl.Close(); err != nil {
		return fmt.Errorf("error closing %s: %w", l.path, err)
	}

	return nil
}

// Init loads the NSCQ dynamic library.
func (l *library) Init() Return {
	if err := l.load(); err != nil {
		return ErrorLibraryNotLoaded
	}
	// By using cgo handle, we explicitly tell the Go GC that this pointer is being tracked externally.
	// It tracks the relationship between a Go object and a numerical handle that can be safely passed
	// to C. Thus, preventing the runtime error "cgo argument has Go pointer to unpinned Go pointer".
	// When C is done, you should call cgo handle Delete() to release the tracker. It is currently
	// done in Shutdown().
	h := cgo.NewHandle(l)
	l.handle = uintptr(h)
	l.isInitialized = true
	return Success
}

// Shutdown closes the NSCQ dynamic library.
func (l *library) Shutdown() Return {
	if !l.isInitialized {
		return ErrorLibraryNotInitialized
	}
	if err := l.close(); err != nil {
		return ErrorLibraryShutdownFailed
	}
	cgo.Handle(l.handle).Delete()
	l.handle = 0
	l.isInitialized = false
	return Success
}

// SessionCreate creates a new NSCQ session.
func (l *library) SessionCreate(flags uint32) (*Session, Return) {
	return l.nscqBindings.sessionCreate(flags)
}

// SessionDestroy destroys a NSCQ session.
func (l *library) SessionDestroy(session *Session) Return {
	if session == nil {
		return ErrorNilReference
	}

	l.nscqBindings.sessionDestroy(session)
	return Success
}

// SwitchPCIEMode retrieves the raw status byte for the PCIe mode of a given switch.
// WARNING: This function is not thread-safe and must not be called concurrently.
func (l *library) SwitchPCIEMode(session *Session, uuid string) (int8, Return) {
	if session == nil {
		return 0, ErrorNilReference
	}
	if !l.isInitialized {
		return 0, ErrorLibraryNotInitialized
	}

	// Prepare for results.
	l.lastRC = Success
	l.lastStatus = 0

	path := fmt.Sprintf("/%s%s", uuid, switchPCIEModePath)
	ret := l.nscqBindings.sessionPathObservePCIEMode(session, path, l)
	if ret != Success {
		return 0, ret
	}

	// Assuming the callback is synchronous, the result is populated when the call returns.
	return l.lastStatus, l.lastRC
}

// SwitchDeviceUUIDs retrieves the UUIDs of all available NVSwitch devices.
// WARNING: This function is not thread-safe and must not be called concurrently.
func (l *library) SwitchDeviceUUIDs(session *Session) ([]string, Return) {
	if session == nil {
		return nil, ErrorNilReference
	}
	if !l.isInitialized {
		return nil, ErrorLibraryNotInitialized
	}

	// Prepare for results.
	l.lastUUIDs = nil // Clear previous results
	l.lastRC = Success

	ret := l.nscqBindings.sessionPathObserveUUID(session, allDeviceUUIDPath, l)
	if ret != Success {
		return nil, ret
	}

	// Because the callbacks are synchronous, the results are populated when the call returns.
	if l.lastRC != Success {
		return nil, l.lastRC
	}
	return l.lastUUIDs, Success
}

func (l *library) SwitchArchitecture(session *Session) (int8, Return) {
	if session == nil {
		return -1, ErrorNilReference
	}
	if !l.isInitialized {
		return -1, ErrorLibraryNotInitialized
	}
	ret := l.nscqBindings.sessionPathObserveArchitecture(session, architecturePath, l)
	if ret != Success {
		return -1, ret
	}
	return l.lastArch, ret
}

func (l *library) SwitchAttestationReport(session *Session, nonce [NonceLength]uint8, uuid string) ([]uint8, Return) {
	if session == nil {
		return nil, ErrorNilReference
	}
	if !l.isInitialized {
		return nil, ErrorLibraryNotInitialized
	}
	ret := l.nscqBindings.setInput(session, 0, string(nonce[:]), NonceLength)
	if ret != Success {
		return nil, ErrorSetInputFailed
	}
	path := fmt.Sprintf("/%s%s", uuid, attestationReportPath)
	ret = l.nscqBindings.sessionPathObserveAttestationReport(session, path, l)
	if ret != Success {
		return nil, ret
	}
	report := make([]uint8, len(l.lastAttestationReport))
	copy(report, l.lastAttestationReport)
	return report, ret
}

func (l *library) SwitchAttestationCertificateChain(session *Session, uuid string) ([]uint8, Return) {
	if session == nil {
		return nil, ErrorNilReference
	}
	if !l.isInitialized {
		return nil, ErrorLibraryNotInitialized
	}
	path := fmt.Sprintf("/%s%s", uuid, attestationCertificateChainPath)
	ret := l.nscqBindings.sessionPathObserveAttestationCertificateChain(session, path, l)
	if ret != Success {
		return nil, ret
	}
	certChain := make([]uint8, len(l.lastAttestationCertChain))
	copy(certChain, l.lastAttestationCertChain)
	return certChain, ret
}

func (l *library) handlePcieModeCallback(status int8, rc Return) {
	l.lastStatus = status
	l.lastRC = rc
}

func (l *library) handleUUIDCallback(uuid string, rc Return) {
	if rc == Success {
		l.lastUUIDs = append(l.lastUUIDs, uuid)
	}
	// Store the first error encountered during the series of callbacks.
	if rc != Success && l.lastRC == Success {
		l.lastRC = rc
	}
}

func (l *library) handleArchitectureCallback(arch int8, rc Return) {
	l.lastArch = arch
	l.lastRC = rc
}

func (l *library) handleAttestationReportCallback(report []uint8, rc Return) {
	l.lastAttestationReport = report
	l.lastRC = rc
}

func (l *library) handleAttestationCertificateChainCallback(certChain []uint8, rc Return) {
	l.lastAttestationCertChain = certChain
	l.lastRC = rc
}
