// Package nscq provides bindings for the libnvidia-nscq library.
package nscq

/*
#cgo linux LDFLAGS: -Wl,--export-dynamic -Wl,--unresolved-symbols=ignore-in-object-files
#cgo darwin LDFLAGS: -Wl,-undefined,dynamic_lookup
#include <stdint.h>
#include <stdlib.h>
#include "nscq.h"

// Forward declarations now point to Go functions that will handle the result.
extern void nscqPcieModeCallback(nscq_tnvl_status_t status, nscq_rc_t rc, void* user_data);
extern void nscqDeviceUUIDCallback(char* uuid_str, nscq_rc_t rc, void* user_data);
extern void nscqDeviceArchitectureCallback(nscq_arch_t arch, nscq_rc_t rc, void* user_data);
extern void nscqDeviceAttestationReportCallback(nscq_attestation_report_t* report, nscq_rc_t rc, void* user_data);
extern void nscqDeviceAttestationCertificateChainCallback(nscq_attestation_certificate_t* certificate, nscq_rc_t rc, void* user_data);

// This is the static C callback function. The `data` parameter for this path is a pointer to the status byte.
static void pcie_mode_callback_c(nscq_uuid_t* device, nscq_rc_t rc, nscq_tnvl_status_t status, void* user_data) {
	// Call the exported Go function.
	nscqPcieModeCallback(status, rc, user_data);
}

// C callback function for observing device UUIDs.
// The `data` here will be a `nscq_uuid_t*`.
static void uuid_callback_c(nscq_uuid_t* device, nscq_rc_t rc, void* data, void* user_data) {
	if (rc != NSCQ_RC_SUCCESS) {
		nscqDeviceUUIDCallback(NULL, rc, user_data);
		return;
	}
	// The data is a UUID, not a label.
	nscq_uuid_t* uuid = (nscq_uuid_t*)data;
	nscq_label_t label;

	// Convert the UUID to a human-readable string label.
	rc = nscq_uuid_to_label(uuid, &label, 0);
	if (rc != NSCQ_RC_SUCCESS) {
		nscqDeviceUUIDCallback(NULL, rc, user_data);
		return;
	}
	nscqDeviceUUIDCallback(label.data, rc, user_data);
}

static void device_architecture_callback_c(nscq_uuid_t* device, nscq_rc_t rc, nscq_arch_t arch, void* user_data) {
  nscqDeviceArchitectureCallback(arch, rc, user_data);
}

static void device_attestation_report_callback_c(nscq_uuid_t* device, nscq_rc_t rc, nscq_attestation_report_t report, void* user_data) {
	if (rc != NSCQ_RC_SUCCESS) {
    nscqDeviceAttestationReportCallback(NULL, rc, user_data);
    return;
  }
  nscqDeviceAttestationReportCallback(&report, rc, user_data);
}

static void device_attestation_certificate_chain_callback_c(nscq_uuid_t* device, nscq_rc_t rc, nscq_attestation_certificate_t certificate, void* user_data) {
	if (rc != NSCQ_RC_SUCCESS) {
    nscqDeviceAttestationCertificateChainCallback(NULL, rc, user_data);
    return;
  }
  nscqDeviceAttestationCertificateChainCallback(&certificate, rc, user_data);
}

// This C helper function remains the same. It correctly passes our C callback to the library.
static nscq_rc_t nscq_session_path_observe_pcie_mode(nscq_session_t session, const char* path, void* user_data) {
	// We pass our C callback 'pcie_mode_callback_c'.
	return nscq_session_path_observe(session, path, (nscq_fn_t)pcie_mode_callback_c, user_data, 0);
}

// C helper function to call the observer with our specific UUID callback.
static nscq_rc_t nscq_session_path_observe_uuid(nscq_session_t session, const char* path, void* user_data) {
	return nscq_session_path_observe(session, path, (nscq_fn_t)uuid_callback_c, user_data, 0);
}

static nscq_rc_t nscq_session_path_observe_architecture(nscq_session_t session, const char* path, void* user_data) {
  return nscq_session_path_observe(session, path, (nscq_fn_t)device_architecture_callback_c, user_data, 0);
}

static nscq_rc_t nscq_session_path_observe_attestation_report(nscq_session_t session, const char* path, void* user_data) {
  return nscq_session_path_observe(session, path, (nscq_fn_t)device_attestation_report_callback_c, user_data, 0);
}

static nscq_rc_t nscq_session_path_observe_attestation_certificate_chain(nscq_session_t session, const char* path, void* user_data) {
	return nscq_session_path_observe(session, path, (nscq_fn_t)device_attestation_certificate_chain_callback_c, user_data, 0);
}
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

//export nscqPcieModeCallback
func nscqPcieModeCallback(status C.nscq_tnvl_status_t, rc C.nscq_rc_t, userData unsafe.Pointer) {
	l := lookupHandle(uintptr(userData))
	if l != nil {
		l.handlePcieModeCallback(int8(status), Return(rc))
	}
}

//export nscqDeviceUUIDCallback
func nscqDeviceUUIDCallback(uuidCStr *C.char, rc C.nscq_rc_t, userData unsafe.Pointer) {
	l := lookupHandle(uintptr(userData))
	if l != nil {
		var uuid string
		if uuidCStr != nil {
			uuid = C.GoString(uuidCStr)
		}
		l.handleUUIDCallback(uuid, Return(rc))
	}
}

//export nscqDeviceArchitectureCallback
func nscqDeviceArchitectureCallback(arch C.nscq_arch_t, rc C.nscq_rc_t, userData unsafe.Pointer) {
	l := lookupHandle(uintptr(userData))
	if l != nil {
		l.handleArchitectureCallback(int8(arch), Return(rc))
	}
}

//export nscqDeviceAttestationReportCallback
func nscqDeviceAttestationReportCallback(reportData *C.nscq_attestation_report_t, rc C.nscq_rc_t, userData unsafe.Pointer) {
	if reportData == nil {
		return
	}
	l := lookupHandle(uintptr(userData))
	if l != nil {
		reportSize := uint32(reportData.report_size)
		// Convert C array to Go slice
		report := unsafe.Slice((*uint8)(unsafe.Pointer(&reportData.report[0])), reportSize)
		l.handleAttestationReportCallback(report, Return(rc))
	}
}

//export nscqDeviceAttestationCertificateChainCallback
func nscqDeviceAttestationCertificateChainCallback(certificateData *C.nscq_attestation_certificate_t, rc C.nscq_rc_t, userData unsafe.Pointer) {
	if certificateData == nil {
		return
	}
	l := lookupHandle(uintptr(userData))
	if l != nil {
		certChainSize := uint32(certificateData.cert_chain_size)
		// Convert C array to Go slice
		certChain := unsafe.Slice((*uint8)(unsafe.Pointer(&certificateData.cert_chain[0])), certChainSize)
		l.handleAttestationCertificateChainCallback(certChain, Return(rc))
	}
}

// sessionCreate creates a new session. This function is a binding mapped to the C-function declared in nscq2/nscq.h:358
func sessionCreate(Arg0 uint32) (*Session, Return) {
	cArg0 := (C.uint32_t)(Arg0)
	ret := C.nscq_session_create(cArg0)
	return (*Session)(unsafe.Pointer(ret.session)), Return(ret.rc)
}

// sessionDestroy destroys a session. This function is a binding mapped to the C-function declared in nscq2/nscq.h:359
func sessionDestroy(Arg0 *Session) {
	cArg0 := *(*C.nscq_session_t)(unsafe.Pointer(&Arg0))
	C.nscq_session_destroy(cArg0)
}

// setInput function as declared in nscq/nscq.h:166
func setInput(Arg0 *Session, Arg1 uint32, Arg2 string, Arg3 uint32) Return {
	cArg0 := *(*C.nscq_session_t)(unsafe.Pointer(&Arg0))
	cArg1 := (C.uint32_t)(Arg1)
	cArg2 := C.CString(Arg2)
	defer C.free(unsafe.Pointer(cArg2))
	cArg3 := (C.uint32_t)(Arg3)
	ret := C.nscq_session_set_input(cArg0, cArg1, unsafe.Pointer(cArg2), cArg3)
	return Return(ret)
}

// sessionPathObservePCIEModeBinding is the Go function that calls our C helper.
func sessionPathObservePCIEModeImpl(session *Session, path string, l *library) Return {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cSession := *(*C.nscq_session_t)(unsafe.Pointer(&session))

	// Call our C wrapper function defined in the preamble.
	ret := C.nscq_session_path_observe_pcie_mode(cSession, cPath, unsafe.Pointer(l.handle))
	return Return(ret)
}

// sessionPathObserveUUIDBinding is a Go binding for our C helper.
func sessionPathObserveUUIDImpl(session *Session, path string, l *library) Return {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cSession := *(*C.nscq_session_t)(unsafe.Pointer(&session))
	ret := C.nscq_session_path_observe_uuid(cSession, cPath, unsafe.Pointer(l.handle))
	return Return(ret)
}

// sessionPathObserveArchitectureBinding is a Go binding for our C helper.
func sessionPathObserveArchitectureImpl(session *Session, path string, l *library) Return {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cSession := *(*C.nscq_session_t)(unsafe.Pointer(&session))
	ret := C.nscq_session_path_observe_architecture(cSession, cPath, unsafe.Pointer(l.handle))
	return Return(ret)
}

// sessionPathObserveAttestationReportBinding is a Go binding for our C helper.
func sessionPathObserveAttestationReportImpl(session *Session, path string, l *library) Return {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cSession := *(*C.nscq_session_t)(unsafe.Pointer(&session))
	ret := C.nscq_session_path_observe_attestation_report(cSession, cPath, unsafe.Pointer(l.handle))
	return Return(ret)
}

// sessionPathObserveAttestationCertificateChainBinding is a Go binding for our C helper.
func sessionPathObserveAttestationCertificateChainImpl(session *Session, path string, l *library) Return {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cSession := *(*C.nscq_session_t)(unsafe.Pointer(&session))
	ret := C.nscq_session_path_observe_attestation_certificate_chain(cSession, cPath, unsafe.Pointer(l.handle))
	return Return(ret)
}

func lookupHandle(h uintptr) *library {
	// 1. Convert the uintptr back to a cgo.Handle
	handle := cgo.Handle(h)

	// 2. Get the Go object back from the handle (type assertion is usually needed)
	// We assume the object is always *library.
	l, ok := handle.Value().(*library)
	if !ok {
		// Handle error: invalid handle or wrong type
		return nil
	}
	return l
}
