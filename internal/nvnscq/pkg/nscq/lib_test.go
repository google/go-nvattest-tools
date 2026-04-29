package nscq

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func newTestLibrary(dl dynamicLibrary) *library {
	return &library{dl: dl, nscqBindings: &mockBindings{}}
}

type mockBindings struct {
	sessionCreateFunc                                 func(uint32) (*Session, Return)
	sessionDestroyFunc                                func(*Session)
	setInputFunc                                      func(*Session, uint32, string, uint32) Return
	sessionPathObservePCIEModeFunc                    func(*Session, string, *library) Return
	sessionPathObserveUUIDFunc                        func(*Session, string, *library) Return
	sessionPathObserveArchitectureFunc                func(*Session, string, *library) Return
	sessionPathObserveAttestationReportFunc           func(*Session, string, *library) Return
	sessionPathObserveAttestationCertificateChainFunc func(*Session, string, *library) Return
}

func (m *mockBindings) sessionCreate(flags uint32) (*Session, Return) {
	if m.sessionCreateFunc != nil {
		return m.sessionCreateFunc(flags)
	}
	return nil, ErrorUnspecified
}

func (m *mockBindings) sessionDestroy(session *Session) {
	if m.sessionDestroyFunc != nil {
		m.sessionDestroyFunc(session)
	}
}

func (m *mockBindings) setInput(session *Session, nonce uint32, uuid string, reportSize uint32) Return {
	if m.setInputFunc != nil {
		return m.setInputFunc(session, nonce, uuid, reportSize)
	}
	return ErrorUnspecified
}

func (m *mockBindings) sessionPathObservePCIEMode(session *Session, path string, l *library) Return {
	if m.sessionPathObservePCIEModeFunc != nil {
		return m.sessionPathObservePCIEModeFunc(session, path, l)
	}
	return ErrorUnspecified
}

func (m *mockBindings) sessionPathObserveUUID(session *Session, path string, l *library) Return {
	if m.sessionPathObserveUUIDFunc != nil {
		return m.sessionPathObserveUUIDFunc(session, path, l)
	}
	return ErrorUnspecified
}

func (m *mockBindings) sessionPathObserveArchitecture(session *Session, path string, l *library) Return {
	if m.sessionPathObserveArchitectureFunc != nil {
		return m.sessionPathObserveArchitectureFunc(session, path, l)
	}
	return ErrorUnspecified
}

func (m *mockBindings) sessionPathObserveAttestationReport(session *Session, path string, l *library) Return {
	if m.sessionPathObserveAttestationReportFunc != nil {
		return m.sessionPathObserveAttestationReportFunc(session, path, l)
	}
	return ErrorUnspecified
}

func (m *mockBindings) sessionPathObserveAttestationCertificateChain(session *Session, path string, l *library) Return {
	if m.sessionPathObserveAttestationCertificateChainFunc != nil {
		return m.sessionPathObserveAttestationCertificateChainFunc(session, path, l)
	}
	return ErrorUnspecified
}

func TestLookupFromDefault(t *testing.T) {
	errClose := errors.New("close error")
	errOpen := errors.New("open error")
	errLookup := errors.New("lookup error")

	testCases := []struct {
		name                 string
		dl                   dynamicLibrary
		skipLoadLibrary      bool
		expectedLoadError    error
		expectedLookupErrror error
		expectedCloseError   error
	}{
		{
			name: "lookup_succeeds",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return nil
				},
				LookupFunc: func(s string) error {
					return nil
				},
				CloseFunc: func() error {
					return nil
				},
			},
		},
		{
			name:                 "error_library_not_loaded_refcount_zero",
			dl:                   &dynamicLibraryMock{},
			skipLoadLibrary:      true,
			expectedLookupErrror: errLibraryNotLoaded,
		},
		{
			name:                 "error_library_not_loaded_nil_library",
			dl:                   nil,
			skipLoadLibrary:      true,
			expectedLookupErrror: errLibraryNotLoaded,
		},
		{
			name: "open_error_returned",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return errOpen
				},
			},
			expectedLoadError:    errOpen,
			expectedLookupErrror: errLibraryNotLoaded,
		},
		{
			name: "lookup_error_returned",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return nil
				},
				LookupFunc: func(s string) error {
					return fmt.Errorf("%w: %s", errLookup, s)
				},
				CloseFunc: func() error {
					return nil
				},
			},
			expectedLookupErrror: errLookup,
		},
		{
			name: "close_error",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return nil
				},
				LookupFunc: func(s string) error {
					return nil
				},
				CloseFunc: func() error {
					return errClose
				},
			},
			expectedCloseError: errClose,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(tc.dl)
			if !tc.skipLoadLibrary {
				require.ErrorIs(t, l.load(), tc.expectedLoadError)
			}
			require.ErrorIs(t, l.LookupSymbol("symbol"), tc.expectedLookupErrror)
			require.ErrorIs(t, l.close(), tc.expectedCloseError)
			if tc.expectedCloseError == nil {
				require.Equal(t, 0, int(l.refcount))
			} else {
				require.Equal(t, 1, int(l.refcount))
			}
		})
	}
}

func TestLoadAndCloseNesting(t *testing.T) {
	dl := &dynamicLibraryMock{
		OpenFunc: func() error {
			return nil
		},
		CloseFunc: func() error {
			return nil
		},
	}

	l := newTestLibrary(dl)

	// When calling close before opening the library nothing happens.
	require.Equal(t, 0, len(dl.calls.Close))
	require.Nil(t, l.close())
	require.Equal(t, 0, len(dl.calls.Close))

	// When calling load twice, the library was only opened once
	require.Equal(t, 0, len(dl.calls.Open))
	require.Nil(t, l.load())
	require.Equal(t, 1, len(dl.calls.Open))
	require.Nil(t, l.load())
	require.Equal(t, 1, len(dl.calls.Open))

	// Only after calling close twice, was the library closed
	require.Equal(t, 0, len(dl.calls.Close))
	require.Nil(t, l.close())
	require.Equal(t, 0, len(dl.calls.Close))
	require.Nil(t, l.close())
	require.Equal(t, 1, len(dl.calls.Close))

	// Calling close again doesn't attempt to close the library again
	require.Nil(t, l.close())
	require.Equal(t, 1, len(dl.calls.Close))
}

func TestLoadAndCloseWithErrors(t *testing.T) {
	testCases := []struct {
		name                  string
		dl                    dynamicLibrary
		expectedLoadRefcount  refcount
		expectedCloseRefcount refcount
	}{
		{
			name: "regular_flow",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return nil
				},
				CloseFunc: func() error {
					return nil
				},
			},
			expectedLoadRefcount:  1,
			expectedCloseRefcount: 0,
		},
		{
			name: "open_error",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return errors.New("")
				},
				CloseFunc: func() error {
					return nil
				},
			},
			expectedLoadRefcount:  0,
			expectedCloseRefcount: 0,
		},
		{
			name: "close_error",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return nil
				},
				CloseFunc: func() error {
					return errors.New("")
				},
			},
			expectedLoadRefcount:  1,
			expectedCloseRefcount: 1,
		},
		{
			name: "open_and_close_error",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return errors.New("")
				},
				CloseFunc: func() error {
					return errors.New("")
				},
			},
			expectedLoadRefcount:  0,
			expectedCloseRefcount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(tc.dl)
			_ = l.load()
			require.Equal(t, tc.expectedLoadRefcount, l.refcount)
			_ = l.close()
			require.Equal(t, tc.expectedCloseRefcount, l.refcount)
		})
	}
}

func TestSessionCreate(t *testing.T) {
	testCases := []struct {
		name    string
		flags   uint32
		session *Session
		rc      Return
	}{
		{
			name:    "success",
			flags:   0,
			session: &Session{},
			rc:      Success,
		},
		{
			name:    "error_unspecified",
			flags:   0,
			session: nil,
			rc:      ErrorUnspecified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			l.nscqBindings.(*mockBindings).sessionCreateFunc = func(flags uint32) (*Session, Return) {
				return tc.session, tc.rc
			}
			session, ret := l.SessionCreate(tc.flags)
			require.Equal(t, tc.session, session)
			require.Equal(t, tc.rc, ret)
		})
	}
}

func TestSessionDestroy(t *testing.T) {
	testCases := []struct {
		name          string
		session       *Session
		bindingCalled bool
	}{
		{
			name:          "success",
			session:       &Session{},
			bindingCalled: true,
		},
		{
			name:          "nil_session",
			session:       nil,
			bindingCalled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			bindingCalled := false
			l.nscqBindings.(*mockBindings).sessionDestroyFunc = func(session *Session) {
				bindingCalled = true
			}
			l.SessionDestroy(tc.session)
			require.Equal(t, tc.bindingCalled, bindingCalled)
		})
	}
}

func TestInit(t *testing.T) {
	testCases := []struct {
		name          string
		dl            dynamicLibrary
		isInitialized bool
		rc            Return
	}{
		{
			name:          "success",
			dl:            &dynamicLibraryMock{},
			isInitialized: true,
			rc:            Success,
		},
		{
			name: "error_load_failed",
			dl: &dynamicLibraryMock{
				OpenFunc: func() error {
					return errors.New("")
				},
			},
			rc: ErrorLibraryNotLoaded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(tc.dl)
			ret := l.Init()
			require.Equal(t, tc.rc, ret)
			require.Equal(t, tc.isInitialized, l.isInitialized)
		})
	}
}

func TestShutdown(t *testing.T) {
	testCases := []struct {
		name     string
		dl       dynamicLibrary
		skipInit bool
		rc       Return
	}{
		{
			name: "success",
			dl:   &dynamicLibraryMock{},
			rc:   Success,
		},
		{
			name:     "error_library_not_initialized",
			dl:       &dynamicLibraryMock{},
			skipInit: true,
			rc:       ErrorLibraryNotInitialized,
		},
		{
			name: "error_shutdown_failed",
			dl: &dynamicLibraryMock{
				CloseFunc: func() error {
					return errors.New("")
				},
			},
			rc: ErrorLibraryShutdownFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(tc.dl)
			if !tc.skipInit {
				l.Init()
			}
			ret := l.Shutdown()
			require.Equal(t, tc.rc, ret)
			if !tc.skipInit && ret == Success {
				require.Equal(t, false, l.isInitialized)
				require.Equal(t, uintptr(0), l.handle)
			}
		})
	}
}

func TestGetSwitchPCIEMode(t *testing.T) {
	testCases := []struct {
		name        string
		uuid        string
		session     *Session
		skipInit    bool
		mockBinding func(s *Session, path string, l *library) Return
		wantStatus  int8
		wantRet     Return
	}{
		{
			name:    "Success",
			uuid:    "test-uuid",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				// Simulate the callback being called synchronously.
				l.handlePcieModeCallback(3, Success)
				return Success
			},
			wantStatus: 3,
			wantRet:    Success,
		},
		{
			name:    "ObserveCallFails",
			uuid:    "test-uuid",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				return ErrorUnspecified
			},
			wantRet: ErrorUnspecified,
		},
		{
			name:    "CallbackReportsError",
			uuid:    "test-uuid",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				l.handlePcieModeCallback(0, ErrorUnspecified)
				return Success
			},
			wantRet: ErrorUnspecified,
		},
		{
			name:    "NilSession",
			session: nil,
			wantRet: ErrorNilReference,
		},
		{
			name:     "error_library_not_initialized",
			session:  &Session{},
			skipInit: true,
			wantRet:  ErrorLibraryNotInitialized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			if !tc.skipInit {
				l.Init()
			}
			if tc.mockBinding != nil {
				l.nscqBindings.(*mockBindings).sessionPathObservePCIEModeFunc = tc.mockBinding
			}

			status, ret := l.SwitchPCIEMode(tc.session, tc.uuid)

			require.Equal(t, tc.wantRet, ret)
			if tc.wantRet == Success {
				require.Equal(t, tc.wantStatus, status)
			}
		})
	}
}

func TestSwitchDeviceUUIDs(t *testing.T) {
	testCases := []struct {
		name        string
		session     *Session
		skipInit    bool
		mockBinding func(s *Session, path string, l *library) Return
		wantUUIDs   []string
		wantRet     Return
	}{
		{
			name:    "SuccessTwoUUIDs",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				l.handleUUIDCallback("uuid-1", Success)
				l.handleUUIDCallback("uuid-2", Success)
				return Success
			},
			wantUUIDs: []string{"uuid-1", "uuid-2"},
			wantRet:   Success,
		},
		{
			name:    "SuccessNoUUIDs",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				return Success
			},
			wantUUIDs: []string{},
			wantRet:   Success,
		},
		{
			name:    "ObserveCallFails",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				return ErrorUnspecified
			},
			wantRet: ErrorUnspecified,
		},
		{
			name:    "NilSession",
			session: nil,
			wantRet: ErrorNilReference,
		},
		{
			name:     "error_library_not_initialized",
			session:  &Session{},
			skipInit: true,
			wantRet:  ErrorLibraryNotInitialized,
		},
		{
			name:    "CallbackFailure",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				l.handleUUIDCallback("uuid-good", Success)
				l.handleUUIDCallback("", ErrorUnspecified)
				return Success
			},
			wantUUIDs: nil,
			wantRet:   ErrorUnspecified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			if !tc.skipInit {
				l.Init()
			}
			if tc.mockBinding != nil {
				l.nscqBindings.(*mockBindings).sessionPathObserveUUIDFunc = tc.mockBinding
			}

			uuids, ret := l.SwitchDeviceUUIDs(tc.session)

			require.Equal(t, tc.wantRet, ret)
			if tc.wantRet == Success {
				require.ElementsMatch(t, tc.wantUUIDs, uuids)
			}
		})
	}
}

func TestSwitchArchitecture(t *testing.T) {
	testCases := []struct {
		name        string
		session     *Session
		skipInit    bool
		mockBinding func(*Session, string, *library) Return
		wantArch    int8
		wantRet     Return
	}{
		{
			name:    "success",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				l.handleArchitectureCallback(1, Success)
				return Success
			},
			wantArch: 1,
			wantRet:  Success,
		},
		{
			name:     "error_nil_session",
			session:  nil,
			wantArch: 0,
			wantRet:  ErrorNilReference,
		},
		{
			name:     "error_library_not_initialized",
			session:  &Session{},
			skipInit: true,
			wantArch: 0,
			wantRet:  ErrorLibraryNotInitialized,
		},
		{
			name:    "error_unspecified",
			session: &Session{},
			mockBinding: func(s *Session, path string, l *library) Return {
				l.handleArchitectureCallback(0, ErrorUnspecified)
				return ErrorUnspecified
			},
			wantArch: -1,
			wantRet:  ErrorUnspecified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			if !tc.skipInit {
				l.Init()
			}
			if tc.mockBinding != nil {
				l.nscqBindings.(*mockBindings).sessionPathObserveArchitectureFunc = tc.mockBinding
			}

			arch, ret := l.SwitchArchitecture(tc.session)

			require.Equal(t, tc.wantRet, ret)
			if tc.wantRet == Success {
				require.Equal(t, tc.wantArch, arch)
			}
		})
	}
}

func TestSwitchAttestationReport(t *testing.T) {
	successReport := []uint8{1, 2, 3}
	testCases := []struct {
		name                         string
		session                      *Session
		nonce                        [NonceLength]uint8
		uuid                         string
		skipInit                     bool
		mockAttestationReportBinding func(*Session, string, *library) Return
		mockInputBinding             func(*Session, uint32, string, uint32) Return
		wantAttestationReport        []uint8
		wantRet                      Return
	}{
		{
			name:    "success",
			session: &Session{},
			nonce:   [NonceLength]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			uuid:    "uuid-1",
			mockAttestationReportBinding: func(session *Session, path string, l *library) Return {
				l.handleAttestationReportCallback(successReport, Success)
				return Success
			},
			mockInputBinding: func(session *Session, nonce uint32, uuid string, reportSize uint32) Return {
				return Success
			},
			wantAttestationReport: successReport,
			wantRet:               Success,
		},
		{
			name:    "error_nil_session",
			session: nil,
			wantRet: ErrorNilReference,
		},
		{
			name:     "error_library_not_initialized",
			session:  &Session{},
			skipInit: true,
			wantRet:  ErrorLibraryNotInitialized,
		},
		{
			name:    "error_set_input_failed",
			session: &Session{},
			mockInputBinding: func(session *Session, nonce uint32, uuid string, reportSize uint32) Return {
				return ErrorSetInputFailed
			},
			wantRet: ErrorSetInputFailed,
		},
		{
			name:    "error_unspecified",
			session: &Session{},
			mockAttestationReportBinding: func(session *Session, path string, l *library) Return {
				l.handleAttestationReportCallback(nil, ErrorUnspecified)
				return ErrorUnspecified
			},
			mockInputBinding: func(session *Session, nonce uint32, uuid string, reportSize uint32) Return {
				return Success
			},
			wantRet: ErrorUnspecified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			if !tc.skipInit {
				l.Init()
			}
			if tc.mockInputBinding != nil {
				l.nscqBindings.(*mockBindings).setInputFunc = tc.mockInputBinding
			}
			if tc.mockAttestationReportBinding != nil {
				l.nscqBindings.(*mockBindings).sessionPathObserveAttestationReportFunc = tc.mockAttestationReportBinding
			}

			attestationReport, ret := l.SwitchAttestationReport(tc.session, tc.nonce, tc.uuid)

			require.Equal(t, tc.wantRet, ret)
			if tc.wantRet == Success {
				successReport = []uint8{0, 0, 0} // Reset to check if deep copy was made.
				if !reflect.DeepEqual(tc.wantAttestationReport, attestationReport) {
					t.Fatal("attestationReport is not a deep copy")
				}
			}
		})
	}
}

func TestSwitchAttestationCertificateChain(t *testing.T) {
	successCertChain := []uint8{1, 2, 3}
	testCases := []struct {
		name                        string
		session                     *Session
		nonce                       [NonceLength]uint8
		uuid                        string
		skipInit                    bool
		mockCertificateChainBinding func(*Session, string, *library) Return
		wantAttestationCertChain    []uint8
		wantRet                     Return
	}{
		{
			name:    "success",
			session: &Session{},
			nonce:   [NonceLength]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			uuid:    "uuid-1",
			mockCertificateChainBinding: func(session *Session, path string, l *library) Return {
				l.handleAttestationCertificateChainCallback(successCertChain, Success)
				return Success
			},
			wantAttestationCertChain: successCertChain,
			wantRet:                  Success,
		},
		{
			name:    "error_nil_session",
			session: nil,
			wantRet: ErrorNilReference,
		},
		{
			name:     "error_library_not_initialized",
			session:  &Session{},
			skipInit: true,
			wantRet:  ErrorLibraryNotInitialized,
		},
		{
			name:    "error_unspecified",
			session: &Session{},
			mockCertificateChainBinding: func(session *Session, path string, l *library) Return {
				l.handleAttestationCertificateChainCallback(nil, ErrorUnspecified)
				return ErrorUnspecified
			},
			wantRet: ErrorUnspecified,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLibrary(&dynamicLibraryMock{})
			if !tc.skipInit {
				l.Init()
			}
			if tc.mockCertificateChainBinding != nil {
				l.nscqBindings.(*mockBindings).sessionPathObserveAttestationCertificateChainFunc = tc.mockCertificateChainBinding
			}

			attestationCertChain, ret := l.SwitchAttestationCertificateChain(tc.session, tc.uuid)

			require.Equal(t, tc.wantRet, ret)
			if tc.wantRet == Success {
				successCertChain = []uint8{0, 0, 0} // Reset to check if deep copy was made.
				if !reflect.DeepEqual(tc.wantAttestationCertChain, attestationCertChain) {
					t.Fatal("attestationCertChain is not a deep copy")
				}
			}
		})
	}
}
