package nscq
// Return enumeration from nscq/nscq.h
// The auto-generated code via #c-for-go does not convert integer return codes to error type as usually seen in Go.
//
//	nscq_rc_t value ranges:
//	 0          : success
//	 1 to 127   : warnings (success, but with caveats)
//	 -128 to -1 : errors
//
// #define NSCQ_RC_SUCCESS (0)
// #define NSCQ_RC_WARNING_RDT_INIT_FAILURE (1)
// #define NSCQ_RC_ERROR_NOT_IMPLEMENTED (-1)
// #define NSCQ_RC_ERROR_INVALID_UUID (-2)
// #define NSCQ_RC_ERROR_RESOURCE_NOT_MOUNTABLE (-3)
// #define NSCQ_RC_ERROR_OVERFLOW (-4)
// #define NSCQ_RC_ERROR_UNEXPECTED_VALUE (-5)
// #define NSCQ_RC_ERROR_UNSUPPORTED_DRV (-6)
// #define NSCQ_RC_ERROR_DRV (-7)
// #define NSCQ_RC_ERROR_TIMEOUT (-8)
// #define NSCQ_RC_ERROR_EXT (-127)
// #define NSCQ_RC_ERROR_UNSPECIFIED (-128)
//
// Additional error codes:
//
//	-129: library not loaded
//	-130: nil reference
const (
	Success                    Return = 0
	Warning                    Return = 1
	ErrorInvalidUUID           Return = -2
	ErrorResourceNotMountable  Return = -3
	ErrorUnexpectedValue       Return = -5
	ErrorUnspecified           Return = -128
	ErrorLibraryNotLoaded      Return = -129
	ErrorLibraryNotInitialized Return = -130
	ErrorLibraryShutdownFailed Return = -131
	ErrorNilReference          Return = -132
	ErrorSetInputFailed        Return = -133
)

const (
	uuidDataLength  = 16
	labelDataLength = 64
)

// Resource paths for NSCQ queries.
const (
	// switchPCIEModePath is the NSCQ path to query the PCIe mode of an NVSwitch,
	// which contains the TNVL and Lock status bits.
	switchPCIEModePath = "/config/pcie_mode"
	// allDeviceUUIDPath is the NSCQ path to query for all device UUIDs.
	allDeviceUUIDPath = "/drv/nvswitch/{device}/uuid"
	// attestationReportPath is the NSCQ path to query for the attestation report.
	attestationReportPath = "/config/attestation_report"
	// attestationCertificateChainPath is the NSCQ path to query for the attestation certificate chain.
	attestationCertificateChainPath = "/config/certificate"
	// architecturePath is the NSCQ path to query for the architecture of an NVSwitch.
	architecturePath = "/{nvswitch}/id/arch"
	// NonceLength is the length of the nonce used for attestation queries.
	// This is defined in nscq/nscq.h as NSCQ_ATTESTATION_REPORT_NONCE_SIZE.
	NonceLength = 32
)
