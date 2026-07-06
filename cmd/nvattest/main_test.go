package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"flag"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	td "github.com/google/go-nvattest-tools/testing/testdata"
	"google.golang.org/protobuf/encoding/protojson"
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
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	t.Run("invalid nonce", func(t *testing.T) {
		c := &attestCmd{nonce: "invalid"}
		if got := c.Execute(context.Background(), fs); got != subcommands.ExitUsageError {
			t.Errorf("Execute() = %v, want %v", got, subcommands.ExitUsageError)
		}
	})
	t.Run("live attestation fails without gpu", func(t *testing.T) {
		c := &attestCmd{
			device: "gpu",
			nonce:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("io.Copy() failed: %v", err)
		}

		if got != subcommands.ExitFailure {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitFailure, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("Failed to collect GPU evidence")) {
			t.Errorf("Execute() stderr = %q, want substring %q", buf.String(), "Failed to collect GPU evidence")
		}
	})

	t.Run("attest nvswitch not implemented", func(t *testing.T) {
		c := &attestCmd{
			device: "nvswitch",
			nonce:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("io.Copy() failed: %v", err)
		}

		if got != subcommands.ExitFailure {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitFailure, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("attest for nvswitch not implemented yet")) {
			t.Errorf("Execute() stderr = %q, want substring %q", buf.String(), "attest for nvswitch not implemented yet")
		}
	})

	t.Run("failed mode detection", func(t *testing.T) {
		tempDir := t.TempDir()
		gpuInfo := &pb.GpuInfo{
			Uuid:              "gpu-uuid-1",
			AttestationReport: []byte("invalid report"),
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

		c := &attestCmd{
			device:       "gpu",
			nonce:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			evidenceFile: evidenceFile,
		}

		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("io.Copy() failed: %v", err)
		}

		if got != subcommands.ExitFailure {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitFailure, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("Failed to detect operating mode")) {
			t.Errorf("Execute() stderr = %q, want substring %q", buf.String(), "Failed to detect operating mode")
		}
	})

	t.Run("mpt verification attempted", func(t *testing.T) {
		tempDir := t.TempDir()
		evidenceBytes, err := protojson.Marshal(td.MptAttestationDataSet.GpuAttestationQuote)
		if err != nil {
			t.Fatalf("protojson.Marshal failed: %v", err)
		}
		evidenceFile := filepath.Join(tempDir, "evidence.json")
		if err := os.WriteFile(evidenceFile, evidenceBytes, 0644); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		c := &attestCmd{
			device:       "gpu",
			nonce:        hex.EncodeToString(td.MptAttestationDataSet.Nonce),
			evidenceFile: evidenceFile,
		}

		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("io.Copy() failed: %v", err)
		}

		if got != subcommands.ExitFailure {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitFailure, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("MPT Verification failed")) {
			t.Errorf("Execute() stderr = %q, want substring %q", buf.String(), "MPT Verification failed")
		}
	})
}

func TestCollectCmdExecute(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	t.Run("invalid nonce", func(t *testing.T) {
		c := &collectCmd{nonce: "invalid"}
		if got := c.Execute(context.Background(), fs); got != subcommands.ExitUsageError {
			t.Errorf("Execute() = %v, want %v", got, subcommands.ExitUsageError)
		}
	})

	t.Run("unknown device", func(t *testing.T) {
		c := &collectCmd{
			device: "unknown",
			nonce:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
		oldStderr := os.Stderr
		_, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr

		if got != subcommands.ExitUsageError {
			t.Errorf("Execute() = %v, want %v", got, subcommands.ExitUsageError)
		}
	})

	t.Run("live collect gpu fails without gpu", func(t *testing.T) {
		c := &collectCmd{
			device: "gpu",
			nonce:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("io.Copy() failed: %v", err)
		}

		if got != subcommands.ExitFailure {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitFailure, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("Failed to collect GPU evidence")) {
			t.Errorf("Execute() stderr = %q, want substring %q", buf.String(), "Failed to collect GPU evidence")
		}
	})

	t.Run("live collect nvswitch fails without switch", func(t *testing.T) {
		c := &collectCmd{
			device: "nvswitch",
			nonce:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
		oldStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		os.Stderr = w

		got := c.Execute(context.Background(), fs)

		w.Close()
		os.Stderr = oldStderr
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("io.Copy() failed: %v", err)
		}

		if got != subcommands.ExitFailure {
			t.Errorf("Execute() = %v, want %v\nStderr: %s", got, subcommands.ExitFailure, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("Failed to collect Switch evidence")) {
			t.Errorf("Execute() stderr = %q, want substring %q", buf.String(), "Failed to collect Switch evidence")
		}
	})
}
