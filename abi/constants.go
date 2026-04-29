package abi

// Constants for the GPU and Switch attestation.
//
// The byte lengths are based on the SPDM spec:
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.0.pdf#page=46&zoom=100,0,570
//
// Nvidia attestation specific parameters could be found here:
// https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/attestation/spdm_msrt_resp_msg.py#L416
const (
	// SpdmRequestSize is the offset (in bytes) of the SPDM response in the attestation report.
	SpdmRequestSize = 37

	// SpdmVersionFieldSize is the size (in bytes) of the SPDM version field in the attestation report.
	SpdmVersionFieldSize = 1

	// RequestResponseCodeFieldSize is the size (in bytes) of the request/response code field in the attestation report.
	RequestResponseCodeFieldSize = 1

	// Param1FieldSize is the size (in bytes) of the param1 field in the attestation report.
	Param1FieldSize = 1

	// Param2FieldSize is the size (in bytes) of the param2 field in the attestation report.
	Param2FieldSize = 1

	// NonceFieldSize is the size (in bytes) of the nonce field in the attestation report.
	NonceFieldSize = 32

	// NumberOfBlocksFieldSize is the size (in bytes) of the number of blocks in a measurement record in the attestation report.
	NumberOfBlocksFieldSize = 1

	// MeasurementRecordLengthFieldSize is the size (in bytes) of the measurement record length field in the attestation report.
	MeasurementRecordLengthFieldSize = 3

	// OpaqueLengthFieldSize is the size (in bytes) of the opaque length field in the attestation report.
	OpaqueLengthFieldSize = 2

	// MeasurementBlockIndexFieldSize is the size (in bytes) of the measurement block index field in the measurement record.
	MeasurementBlockIndexFieldSize = 1

	// MeasurementBlockSpecificationFieldSize is the size (in bytes) of the measurement block specification field in the measurement block.
	MeasurementBlockSpecificationFieldSize = 1

	// MeasurementBlockSizeFieldSize is the size (in bytes) of the measurement block size field in the measurement block.
	MeasurementBlockSizeFieldSize = 2

	// MeasurementBlockDmtfSpecValueFieldSize is the size (in bytes) of the measurement block dmtf spec value field in the measurement block.
	MeasurementBlockDmtfSpecValueFieldSize = 1

	// MeasurementBlockDmtfSpecValueSizeFieldSize is the size (in bytes) of the measurement block dmtf spec value size field in the measurement block.
	MeasurementBlockDmtfSpecValueSizeFieldSize = 2

	// DmtfMeasurementSpecificationValue is the value of the measurement block specification
	DmtfMeasurementSpecificationValue = 1

	// DmtfSpecMeasurementValueTypeFieldSize is the size (in bytes) of the dmtf spec measurement value type field in the dmtf measurement.
	DmtfSpecMeasurementValueTypeFieldSize = 1

	// DmtfSpecMeasurementValueSizeFieldSize is the size (in bytes) of the dmtf spec measurement value size field in the dmtf measurement.
	DmtfSpecMeasurementValueSizeFieldSize = 2

	// OpaqueDataTypeFieldSize is the size (in bytes) of the opaque data type field in the opaque data.
	OpaqueDataTypeFieldSize = 2

	// OpaqueDataSizeFieldSize is the size (in bytes) of the opaque data size field in the opaque data.
	OpaqueDataSizeFieldSize = 2

	// OpaquePdiDataSizeFieldSize is the size (in bytes) of the opaque switch pdis data size field in the opaque data.
	OpaquePdiDataSizeFieldSize = 8

	// OpaqueDataMsrCountSize is the size (in bytes) of the opaque measurement count size in the opaque data.
	OpaqueDataMsrCountSize = 4

	// OpaquePortIDSizeFieldSize is the size (in bytes) of the opaque port id size field in the opaque data.
	OpaquePortIDSizeFieldSize = 1

	// GpuAttestationReportSignatureFieldSize is the size (in bytes) of the signature field in the GPU attestation report.
	GpuAttestationReportSignatureFieldSize = 96

	// SwitchAttestationReportSignatureFieldSize is the size (in bytes) of the signature field in the switch attestation report.
	SwitchAttestationReportSignatureFieldSize = 96

	// totalNumberOfPdis is the total number of PDIs in the switch attestation report.
	TotalNumberOfPdis = 8

	// SlotIDParamFieldSize is the size (in bytes) of the slot id param field in the attestation report's SPDM measurement request.
	SlotIDParamFieldSize = 1
)
