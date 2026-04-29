// Package utility provides helper functions.
package utility

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-nvattest-tools/abi"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/rim"
)

const hashFunctionNamespace = "http://www.w3.org/2001/04/xmlenc#sha384"

var parseAttestationReport = abi.RawAttestationReportToProto

// ValidateModes validates the attestation modes of all GPUs in the quote.
func ValidateModes(quote *pb.GpuAttestationQuote, expectedMode string) error {
	// 1. Optimization: No need to loop if there is 0 or 1 GPU.
	if len(quote.GetGpuInfos()) <= 1 {
		return nil
	}

	for _, gpuInfo := range quote.GetGpuInfos() {
		// 1. Parse the attestation report.
		report, err := parseAttestationReport(gpuInfo.GetAttestationReport(), abi.GPU)
		if err != nil {
			return fmt.Errorf("failed to parse attestation report for GPU %v: %w", gpuInfo.GetUuid(), err)
		}

		// 1.1 Skip if the version is not available or is less than 1. Older opaque data versions
		// do not contain the feature flags required to determine the attestation mode.
		versionBytes := abi.ExtractOpaqueValue(report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData(), pb.OpaqueDataType_OPAQUE_FIELD_ID_OPAQUE_DATA_VERSION)
		if len(versionBytes) < 1 {
			continue
		}
		versionStr := string(versionBytes)
		parts := strings.Split(versionStr, ".")
		major, err := strconv.Atoi(parts[0])
		if err != nil || major < 1 {
			continue
		}

		// 2. Parse the bytes into a descriptive string.
		// This now returns "MPT", "SPT", or "PPCIE" (or other mapped modes).
		currentMode, err := abi.ParseFeatureFlag(report)
		if err != nil {
			return fmt.Errorf("failed to parse mode for GPU %v: %w", gpuInfo.GetUuid(), err)
		}

		// 3. Directly compare against the expected "MPT" baseline.
		if currentMode != expectedMode {
			return fmt.Errorf("GPU %v is not in %s mode (found %q)", gpuInfo.GetUuid(), expectedMode, currentMode)
		}
	}

	return nil
}

func normalizeOpaqueString(bytes []byte) string {
	return strings.ToUpper(strings.Trim(strings.TrimSpace(string(bytes)), "\x00"))
}

func readFieldAsLittleEndian(data []byte) string {
	var result strings.Builder
	for i := len(data) - 1; i >= 0; i-- {
		// Convert each byte to its hexadecimal representation and write it to the string builder.
		result.WriteString(hex.EncodeToString(data[i : i+1]))
	}

	return result.String()
}

// FormatVbiosVersion converts the input VBIOS version in byte format to xx.xx.xx.xx.xx format.
func FormatVbiosVersion(version []byte, mode abi.AttestationType) string {
	switch mode {
	case abi.GPU:
		return formatGpuVbiosVersion(version)
	case abi.SWITCH:
		return formatSwitchBiosVersion(version)
	default:
		return ""
	}
}

// Reference: https://github.com/NVIDIA/nvtrust/blob/7960697fe7a36a1085656576622e386f4d52194d/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/utils/__init__.py#L167
func formatGpuVbiosVersion(version []byte) string {
	value := readFieldAsLittleEndian(version)

	halfLength := len(value) / 2
	temp := value[halfLength:] + value[halfLength-2:halfLength]

	// Create a slice to hold all the two-character parts.
	parts := make([]string, 0, len(temp)/2)

	// Loop over the temp string, taking two characters at a time.
	for i := 0; i < len(temp); i += 2 {
		parts = append(parts, temp[i:i+2])
	}

	// Join all the collected parts with a period.
	return strings.Join(parts, ".")
}

// Reference: https://github.com/NVIDIA/nvtrust/blob/5603ffe029b87ce62aeaec6abef081d9e21d1db6/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/utils/__init__.py#L121
func formatSwitchBiosVersion(version []byte) string {
	return string(version)
}

// driverRIMFileID returns the file ID for the driver RIM.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L433
func driverRIMFileID(driverVersion string, opaqueFieldDataList []*pb.OpaqueFieldData, gpuArch pb.GpuArchitectureType) (string, error) {
	var prefix string

	switch gpuArch {
	case pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER:
		prefix = "NV_GPU_DRIVER_GH100_"
	case pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL:
		// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/attestation/spdm_msrt_resp_msg.py#L364
		chipInfoBytes := abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_CHIP_INFO)
		chipInfo, _, _ := bytes.Cut(chipInfoBytes, []byte{0})
		prefix = fmt.Sprintf("NV_GPU_CC_DRIVER_%s_", string(chipInfo))
	default:
		return "", fmt.Errorf("unsupported GPU architecture: %s", gpuArch)
	}

	return prefix + driverVersion, nil
}

// vbiosRIMFileID returns the file ID for the VBIOS RIM (GPU and Switch).
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L418
func vbiosRIMFileID(opaqueFieldDataList []*pb.OpaqueFieldData, mode abi.AttestationType) string {
	project := normalizeOpaqueString(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_PROJECT))
	projectSKU := normalizeOpaqueString(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_PROJECT_SKU))
	chipSKU := normalizeOpaqueString(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_CHIP_SKU))
	vbiosVersionForID := strings.ToUpper(strings.ReplaceAll(FormatVbiosVersion(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION), mode), ".", ""))

	switch mode {
	case abi.GPU:
		return fmt.Sprintf("NV_GPU_VBIOS_%s_%s_%s_%s", project, projectSKU, chipSKU, vbiosVersionForID)
	case abi.SWITCH:
		// NV Switch doesn't have project, projectSKU and chipSKU fields and should be hardcoded.
		// Reference: https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/config.py#L42-L44
		return fmt.Sprintf("NV_SWITCH_BIOS_5612_0002_890_%s", vbiosVersionForID)
	default:
		return ""
	}
}

var rimParse = rim.Parse

// DriverRIMData returns the RIM data for the GPU device driver.
var DriverRIMData = func(ctx context.Context, driverVersion string, reportProto *pb.AttestationReport, rimClient rim.Client, gpuArch pb.GpuArchitectureType) (*rim.Data, error) {
	opaqueFieldDataList := reportProto.SpdmMeasurementResponse.GetOpaqueData().GetOpaqueFieldData()
	fileID, err := driverRIMFileID(driverVersion, opaqueFieldDataList, gpuArch)
	if err != nil {
		return nil, fmt.Errorf("failed to get driver RIM file ID: %w", err)
	}

	driverRimContentBytes, err := rimClient.FetchRIM(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch driver RIM content: %w", err)
	}
	rimData, err := rimParse(driverRimContentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse driver RIM content: %w", err)
	}
	return rimData, nil
}

func vbiosRIMData(ctx context.Context, reportProto *pb.AttestationReport, rimClient rim.Client, mode abi.AttestationType) (*rim.Data, error) {
	opaqueFieldDataList := reportProto.SpdmMeasurementResponse.GetOpaqueData().GetOpaqueFieldData()
	fileID := vbiosRIMFileID(opaqueFieldDataList, mode)
	vbiosRimContentBytes, err := rimClient.FetchRIM(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vbios RIM content: %w", err)
	}
	rimData, err := rimParse(vbiosRimContentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vbios RIM content: %w", err)
	}
	return rimData, nil
}

// RIMExtractor is an interface for extracting measurements from a RIM.
type RIMExtractor interface {
	Measurements(rimName, hashFunctionNamespace string) ([]rim.GoldenMeasurement, error)
}

// GpuVbiosRIMData returns the RIM data for the GPU device VBIOS.
var GpuVbiosRIMData = func(ctx context.Context, reportProto *pb.AttestationReport, rimClient rim.Client) (*rim.Data, error) {
	return vbiosRIMData(ctx, reportProto, rimClient, abi.GPU)
}

// SwitchBiosRIMData returns the RIM data for the Switch device VBIOS.
var SwitchBiosRIMData = func(ctx context.Context, reportProto *pb.AttestationReport, rimClient rim.Client) (*rim.Data, error) {
	return vbiosRIMData(ctx, reportProto, rimClient, abi.SWITCH)
}

// DriverGoldenMeasurements returns the golden measurements for the GPU device driver.
var DriverGoldenMeasurements = func(rimData RIMExtractor) ([]rim.GoldenMeasurement, error) {
	return rimData.Measurements("driver", hashFunctionNamespace)
}

// VbiosGoldenMeasurements returns the golden measurements for the GPU/Switch device VBIOS.
var VbiosGoldenMeasurements = func(rimData RIMExtractor) ([]rim.GoldenMeasurement, error) {
	return rimData.Measurements("vbios", hashFunctionNamespace)
}
