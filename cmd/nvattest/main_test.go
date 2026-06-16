package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flag"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	nvrimpb "github.com/google/go-nvattest-tools/proto/nvrim"
	testdata "github.com/google/go-nvattest-tools/server/ocsp/nvidiaocsp/testdata"
	"github.com/google/go-nvattest-tools/server/verify"
	td "github.com/google/go-nvattest-tools/testing/testdata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"github.com/google/subcommands"
)

func TestParseNonce(t *testing.T) {
	tests := []struct {
		name    string
		nonce   string
		wantErr bool
	}{
		{
			name:    "empty",
			nonce:   "",
			wantErr: false,
		},
		{
			name:    "valid 32-byte hex",
			nonce:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
		{
			name:    "invalid hex",
			nonce:   "not hex string",
			wantErr: true,
		},
		{
			name:    "bad length (too short)",
			nonce:   "0123456789",
			wantErr: true,
		},
		{
			name:    "bad length (too long)",
			nonce:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNonce(tc.nonce)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseNonce(%q) error = %v, wantErr %v", tc.nonce, err, tc.wantErr)
			}
		})
	}
}

func TestCommandsInterface(t *testing.T) {
	cmds := []subcommands.Command{
		&collectCmd{},
		&attestCmd{},
	}

	for _, cmd := range cmds {
		name := cmd.Name()
		t.Run(name, func(t *testing.T) {
			if name == "" {
				t.Errorf("expected command to return a non-empty Name()")
			}
			if synopsis := cmd.Synopsis(); synopsis == "" {
				t.Errorf("expected command %s to return a non-empty Synopsis()", name)
			}
			if usage := cmd.Usage(); usage == "" {
				t.Errorf("expected command %s to return a non-empty Usage()", name)
			}
		})
	}
}

func TestCommandsFlags(t *testing.T) {
	t.Run("collectCmd", func(t *testing.T) {
		cmd := &collectCmd{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		cmd.SetFlags(fs)

		err := fs.Parse([]string{"--device=nvswitch", "--nonce=deadbeef", "--evidence_file=evidence.json"})
		if err != nil {
			t.Fatalf("Parse() failed: %v", err)
		}

		if got, want := cmd.device, "nvswitch"; got != want {
			t.Errorf("cmd.device = %q, want %q", got, want)
		}
		if got, want := cmd.nonce, "deadbeef"; got != want {
			t.Errorf("cmd.nonce = %q, want %q", got, want)
		}
		if got, want := cmd.evidenceFile, "evidence.json"; got != want {
			t.Errorf("cmd.evidenceFile = %q, want %q", got, want)
		}
	})

	t.Run("attestCmd", func(t *testing.T) {
		cmd := &attestCmd{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		cmd.SetFlags(fs)

		err := fs.Parse([]string{
			"--device=nvswitch",
			"--nonce=deadbeef",
			"--evidence_file=evidence.json",
			"--rims_file=rims.pb",
			"--rims_ocsp_file=rims_ocsp.pb",
			"--device_ocsp_file=device_ocsp.pb",
			"--device_l4_crl_file=crl.pb",
		})
		if err != nil {
			t.Fatalf("Parse() failed: %v", err)
		}

		if got, want := cmd.device, "nvswitch"; got != want {
			t.Errorf("cmd.device = %q, want %q", got, want)
		}
		if got, want := cmd.nonce, "deadbeef"; got != want {
			t.Errorf("cmd.nonce = %q, want %q", got, want)
		}
		if got, want := cmd.evidenceFile, "evidence.json"; got != want {
			t.Errorf("cmd.evidenceFile = %q, want %q", got, want)
		}
		if got, want := cmd.rimsFile, "rims.pb"; got != want {
			t.Errorf("cmd.rimsFile = %q, want %q", got, want)
		}
		if got, want := cmd.rimsOCSPFile, "rims_ocsp.pb"; got != want {
			t.Errorf("cmd.rimsOCSPFile = %q, want %q", got, want)
		}
		if got, want := cmd.deviceOCSPFile, "device_ocsp.pb"; got != want {
			t.Errorf("cmd.deviceOCSPFile = %q, want %q", got, want)
		}
		if got, want := cmd.deviceL4CRLFile, "crl.pb"; got != want {
			t.Errorf("cmd.deviceL4CRLFile = %q, want %q", got, want)
		}
	})
}

func TestAttestCmdExecute(t *testing.T) {
	ctx := context.Background()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	t.Run("invalid nonce", func(t *testing.T) {
		c := &attestCmd{nonce: "invalid"}
		if got := c.Execute(ctx, fs); got != subcommands.ExitUsageError {
			t.Errorf("Execute() = %v, want %v", got, subcommands.ExitUsageError)
		}
	})

	t.Run("success offline verification", func(t *testing.T) {
		tempDir := t.TempDir()

		driverRimXML, err := td.ReadXMLFile("rim/NV_GPU_DRIVER_GH100_550.90.07.xml")
		if err != nil {
			t.Fatalf("Failed to read driver RIM: %v", err)
		}
		vbiosRimXML, err := td.ReadXMLFile("rim/NV_GPU_VBIOS_1010_0200_882_96009F0001.xml")
		if err != nil {
			t.Fatalf("Failed to read vbios RIM: %v", err)
		}

		rimsCache := nvrimpb.NvidiaRims_builder{
			RimsData: map[string]string{
				td.ExpectedGpuDriverRimFileID: base64.StdEncoding.EncodeToString(driverRimXML),
				td.ExpectedGpuVbiosRimFileID:  base64.StdEncoding.EncodeToString(vbiosRimXML),
			},
		}.Build()
		rimsDataBytes, err := prototext.Marshal(rimsCache)
		if err != nil {
			t.Fatalf("prototext.Marshal failed: %v", err)
		}
		rimsFile := filepath.Join(tempDir, "rims.textproto")
		if err := os.WriteFile(rimsFile, rimsDataBytes, 0644); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		rimsOCSPFile := filepath.Join(tempDir, "rims_ocsp.textproto")
		if err := os.WriteFile(rimsOCSPFile, testdata.RIMsOCSPTextproto, 0644); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		deviceOCSPFile := filepath.Join(tempDir, "device_ocsp.textproto")
		if err := os.WriteFile(deviceOCSPFile, testdata.DeviceOCSPTextproto, 0644); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		deviceL4CRLFile := filepath.Join(tempDir, "device_l4_crl.textproto")
		if err := os.WriteFile(deviceL4CRLFile, testdata.DeviceL4CRLTextproto, 0644); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		gpuInfo := &pb.GpuInfo{
			Uuid:                        "gpu-uuid-1",
			DriverVersion:               td.RawGpuAttestationReportTestData.DriverVersion,
			VbiosVersion:                td.RawGpuAttestationReportTestData.VBiosVersion,
			GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			AttestationCertificateChain: td.GpuAttestationCertificateChain,
			AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
		}
		gpuQuote := &pb.GpuAttestationQuote{
			GpuInfos: []*pb.GpuInfo{gpuInfo},
		}
		evidenceBytes, err := protojson.Marshal(gpuQuote)
		if err != nil {
			t.Fatalf("protojson.Marshal failed: %v", err)
		}
		evidenceFile := filepath.Join(tempDir, "evidence.json")
		if err := os.WriteFile(evidenceFile, evidenceBytes, 0644); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		validOcspTime, err := time.Parse(time.RFC3339, "2025-09-25T00:00:00Z")
		if err != nil {
			t.Fatalf("Failed to parse validOcspTime: %v", err)
		}
		timeSet := &verify.TimeSet{
			GPUCertChain:        validOcspTime,
			RIMCertChain:        validOcspTime,
			RIMOCSPCertChain:    validOcspTime,
			DeviceOCSPCertChain: validOcspTime,
		}

		c := &attestCmd{
			device:          "gpu",
			nonce:           hex.EncodeToString(td.RawGpuAttestationReportTestData.Nonce),
			evidenceFile:    evidenceFile,
			rimsFile:        rimsFile,
			rimsOCSPFile:    rimsOCSPFile,
			deviceOCSPFile:  deviceOCSPFile,
			deviceL4CRLFile: deviceL4CRLFile,
			now:             timeSet,
		}

		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		got := c.Execute(ctx, fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		io.Copy(&buf, r)

		if got != subcommands.ExitSuccess {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitSuccess, buf.String())
		}
	})
}
