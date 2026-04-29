package nscq

import (
	"sync"
)

// Ensure, that dynamicLibraryMock does implement dynamicLibrary.
// If this is not the case, regenerate this file with moq.
var _ dynamicLibrary = &dynamicLibraryMock{}

// dynamicLibraryMock is a mock implementation of dynamicLibrary.
//
//	func TestSomethingThatUsesdynamicLibrary(t *testing.T) {
//
//		// make and configure a mocked dynamicLibrary
//		mockeddynamicLibrary := &dynamicLibraryMock{
//			CloseFunc: func() error {
//				panic("mock out the Close method")
//			},
//			LookupFunc: func(s string) error {
//				panic("mock out the Lookup method")
//			},
//			OpenFunc: func() error {
//				panic("mock out the Open method")
//			},
//		}
//
//		// use mockeddynamicLibrary in code that requires dynamicLibrary
//		// and then make assertions.
//
//	}
type dynamicLibraryMock struct {
	// CloseFunc mocks the Close method.
	CloseFunc func() error

	// LookupFunc mocks the Lookup method.
	LookupFunc func(s string) error

	// OpenFunc mocks the Open method.
	OpenFunc func() error

	// calls tracks calls to the methods.
	calls struct {
		// Close holds details about calls to the Close method.
		Close []struct {
		}
		// Lookup holds details about calls to the Lookup method.
		Lookup []struct {
			// S is the s argument value.
			S string
		}
		// Open holds details about calls to the Open method.
		Open []struct {
		}
	}
	lockClose  sync.RWMutex
	lockLookup sync.RWMutex
	lockOpen   sync.RWMutex
}

// Close mocks the Close method of DynamicLibrary and it adds the call info to the calls.Close slice for testing.
func (mock *dynamicLibraryMock) Close() error {
	callInfo := struct {
	}{}
	mock.lockClose.Lock()
	mock.calls.Close = append(mock.calls.Close, callInfo)
	mock.lockClose.Unlock()
	if mock.CloseFunc == nil {
		return nil
	}
	return mock.CloseFunc()
}

// CloseCalls is used to track and check the number of calls to a specific function - Close() - for unit testing.
// Tests can check the number of calls to Close function with:
//
// len(mockeddynamicLibrary.CloseCalls())
func (mock *dynamicLibraryMock) CloseCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockClose.RLock()
	calls = mock.calls.Close
	mock.lockClose.RUnlock()
	return calls
}

// Lookup mocks the Lookup method of DynamicLibrary and it adds the call info to the calls.Lookup slice for testing.
func (mock *dynamicLibraryMock) Lookup(s string) error {
	callInfo := struct {
		S string
	}{
		S: s,
	}
	mock.lockLookup.Lock()
	mock.calls.Lookup = append(mock.calls.Lookup, callInfo)
	mock.lockLookup.Unlock()
	if mock.LookupFunc == nil {
		return nil
	}
	return mock.LookupFunc(s)
}

// LookupCalls is used to track and check the number of calls to a specific function - Lookup() - for unit testing.
// Tests can check the number of calls to Lookup function with:
//
//	len(mockeddynamicLibrary.LookupCalls())
func (mock *dynamicLibraryMock) LookupCalls() []struct {
	S string
} {
	var calls []struct {
		S string
	}
	mock.lockLookup.RLock()
	calls = mock.calls.Lookup
	mock.lockLookup.RUnlock()
	return calls
}

// Open mocks the Open method of DynamicLibrary and it adds the call info to the calls.Open slice for testing.
func (mock *dynamicLibraryMock) Open() error {
	callInfo := struct {
	}{}
	mock.lockOpen.Lock()
	mock.calls.Open = append(mock.calls.Open, callInfo)
	mock.lockOpen.Unlock()
	if mock.OpenFunc == nil {
		return nil
	}
	return mock.OpenFunc()
}

// OpenCalls is used to track and check the number of calls to a specific function - Open() - for unit testing.
// Tests can check the number of calls to Open function with:
//
//	len(mockeddynamicLibrary.OpenCalls())
func (mock *dynamicLibraryMock) OpenCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockOpen.RLock()
	calls = mock.calls.Open
	mock.lockOpen.RUnlock()
	return calls
}
