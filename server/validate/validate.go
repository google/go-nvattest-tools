// Package validate provides functions to validate golden and runtime measurements.
package validate

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-nvattest-tools/abi"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/server/utility"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

const (
	msr35Index         = 35
	enabledMsr35Value  = "\xAA"
	disabledMsr35Value = "\x55"
)

// RimType represents a measurement type.
type RimType int

// Represents the measurement type.
const (
	// Driver is the driver measurement type.
	Driver RimType = iota
	// VBios is the vbios measurement type.
	VBios
)

// Options represents the validation options for driver and vbios measurements.
type Options struct {
	Nonce              []byte
	DriverVersion      string                              // DriverVersion is the driver version of the GPU device.
	VBiosVersion       string                              // VBiosVersion is the vbios version of the GPU device, or a bios version of the switch device.
	goldenMeasurements map[RimType][]rim.GoldenMeasurement // GoldenMeasurements is an internal field that holds the golden measurements for GPU and switch devices.
	AttestationType    abi.AttestationType                 // AttestationType is used to parse the raw attestation report for GPU or switch devices.
	RimClient          rim.Client                          // RIM client to fetch RIM data, including driver+vbios for GPU, and bios for switch.
	DisableRefCheck    bool                                // If true, skip reference check.
	GpuArch            pb.GpuArchitectureType              // GPUArch is the expected GPU architecture of the GPU device, it helps locate a specific GPU RIM ID.

	parseAttestationReport func([]byte, abi.AttestationType) (*pb.AttestationReport, error)
	newRimClient           func(*http.Client, string) rim.Client
}

func combineActiveDriverAndVBiosGoldenMeasurements(measurements map[RimType][]rim.GoldenMeasurement) (map[int]rim.GoldenMeasurement, error) {
	measurementsMap := make(map[int]rim.GoldenMeasurement)

	if driverGoldenMeasurements, ok := measurements[Driver]; ok {
		for _, measurement := range driverGoldenMeasurements {
			if measurement.Active {
				measurementsMap[measurement.Index] = measurement
			}
		}
	}

	if vbiosGoldenMeasurements, ok := measurements[VBios]; ok {
		for _, measurement := range vbiosGoldenMeasurements {
			if measurement.Active {
				if _, exists := measurementsMap[measurement.Index]; exists {
					return nil, &MultipleMeasurementsWithSameIndexError{index: measurement.Index}
				}
				measurementsMap[measurement.Index] = measurement
			}
		}
	}

	return measurementsMap, nil
}

func runtimeMeasurements(measurementBlocks []*pb.MeasurementBlock) map[int]string {
	measurementsMap := make(map[int]string)
	for _, measurementBlock := range measurementBlocks {
		measurementsMap[int(measurementBlock.GetIndex())-1] = hex.EncodeToString(measurementBlock.GetDmtfMeasurement().GetValue())
	}
	return measurementsMap
}

// AttestationReport validates runtime measurements in the attestation report against the golden measurements.
func AttestationReport(ctx context.Context, rawAttestationReport []uint8, opts Options) error {
	if opts.parseAttestationReport == nil {
		opts.parseAttestationReport = abi.RawAttestationReportToProto
	}
	if opts.newRimClient == nil {
		opts.newRimClient = rim.NewDefaultNvidiaClient
	}
	attestationReport, err := opts.parseAttestationReport(rawAttestationReport, opts.AttestationType)
	if err != nil {
		return err
	}

	nonce := attestationReport.GetSpdmMeasurementRequest().GetNonce()
	if !bytes.Equal(nonce, opts.Nonce) {
		return &NonceMismatchError{actual: nonce, expected: opts.Nonce}
	}

	ofds := attestationReport.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()
	var driverVersion string
	var vbiosVersion string

	for _, ofd := range ofds {
		if ofd.GetDataType() == pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION {
			// If present, remove the trailing null byte from the driver version.
			driverVersion = string(bytes.TrimSuffix(ofd.GetValue(), []byte{0x00}))
		}
		if ofd.GetDataType() == pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION {
			vbiosVersion = utility.FormatVbiosVersion(ofd.GetValue(), opts.AttestationType)
		}
	}

	if opts.AttestationType == abi.GPU && driverVersion != opts.DriverVersion {
		return &DriverVersionMismatchError{actual: driverVersion, expected: opts.DriverVersion}
	}

	if !strings.EqualFold(vbiosVersion, opts.VBiosVersion) {
		return &VBiosVersionMismatchError{actual: vbiosVersion, expected: opts.VBiosVersion}
	}

	if opts.DisableRefCheck {
		return nil
	}

	if opts.RimClient == nil {
		opts.RimClient = opts.newRimClient(nil, "")
	}

	if opts.AttestationType == abi.GPU {
		opts.goldenMeasurements, err = gpuGoldenMeasurements(ctx, attestationReport, opts)
	} else {
		opts.goldenMeasurements, err = switchGoldenMeasurements(ctx, attestationReport, opts)
	}
	if err != nil {
		return err
	}
	if err := doMeasurementsMatch(attestationReport, opts); err != nil {
		return err
	}
	return nil
}

func doMeasurementsMatch(attestationReport *pb.AttestationReport, opts Options) error {
	goldenMeasurements, err := combineActiveDriverAndVBiosGoldenMeasurements(opts.goldenMeasurements)
	if err != nil {
		return err
	}

	if len(goldenMeasurements) == 0 {
		return &NoMeasurementsError{measurementType: "golden", dataSource: "RIM"}
	}

	runtimeMeasurements := runtimeMeasurements(attestationReport.GetSpdmMeasurementResponse().GetMeasurementRecord().GetMeasurementBlocks())

	if len(runtimeMeasurements) == 0 {
		return &NoMeasurementsError{measurementType: "runtime", dataSource: "attestation report"}
	}

	if len(goldenMeasurements) > len(runtimeMeasurements) {
		return &InvalidComparisonError{}
	}

	// Check if NVDEC0 status for index 35 is disabled. Only applicable for GPU attestation.
	isMsr35Valid := true
	if opts.AttestationType == abi.GPU {
		for _, ofd := range attestationReport.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData() {
			if ofd.GetDataType() == pb.OpaqueDataType_OPAQUE_FIELD_ID_NVDEC0_STATUS && string(ofd.GetValue()) == disabledMsr35Value {
				isMsr35Valid = false
				break
			}
		}
	}

	var misMatchedIndices []int

	for index, measurement := range goldenMeasurements {
		// skip comparison if NVDEC0 status for index 35 is disabled.
		if index == msr35Index && !isMsr35Valid {
			continue
		}

		isMatch := false
		for j := 0; j < measurement.Alternatives; j++ {
			if measurement.Values[j] == runtimeMeasurements[index] && measurement.Size == len(runtimeMeasurements[index])/2 {
				isMatch = true
				break
			}
		}

		if !isMatch {
			misMatchedIndices = append(misMatchedIndices, index)
		}
	}

	if len(misMatchedIndices) > 0 {
		sort.Ints(misMatchedIndices)
		mismatchedMeasurements := make([]mismatchedMeasurement, 0, len(misMatchedIndices))
		for _, index := range misMatchedIndices {
			mismatchedMeasurements = append(mismatchedMeasurements, mismatchedMeasurement{
				index:                   index,
				goldenMeasurementValues: goldenMeasurements[index].Values,
				runtimeMeasurementValue: runtimeMeasurements[index],
			})
		}
		return &MismatchedMeasurementsError{mismatchedMeasurements: mismatchedMeasurements}
	}

	return nil
}

func gpuGoldenMeasurements(ctx context.Context, attestationReport *pb.AttestationReport, opts Options) (map[RimType][]rim.GoldenMeasurement, error) {
	driverRimData, err := utility.DriverRIMData(ctx, opts.DriverVersion, attestationReport, opts.RimClient, opts.GpuArch)
	if err != nil {
		return nil, err
	}
	vbiosRimData, err := utility.GpuVbiosRIMData(ctx, attestationReport, opts.RimClient)
	if err != nil {
		return nil, err
	}

	driverGolden, err := utility.DriverGoldenMeasurements(driverRimData)
	if err != nil {
		return nil, err
	}
	vbiosGolden, err := utility.VbiosGoldenMeasurements(vbiosRimData)
	if err != nil {
		return nil, err
	}
	return map[RimType][]rim.GoldenMeasurement{
		Driver: driverGolden,
		VBios:  vbiosGolden,
	}, nil
}

func switchGoldenMeasurements(ctx context.Context, attestationReport *pb.AttestationReport, opts Options) (map[RimType][]rim.GoldenMeasurement, error) {
	vbiosRimData, err := utility.SwitchBiosRIMData(ctx, attestationReport, opts.RimClient)
	if err != nil {
		return nil, err
	}
	vbiosGolden, err := utility.VbiosGoldenMeasurements(vbiosRimData)
	if err != nil {
		return nil, err
	}
	return map[RimType][]rim.GoldenMeasurement{
		VBios: vbiosGolden,
	}, nil
}
