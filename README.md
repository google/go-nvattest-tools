# go-nvattest-tools

This project offers libraries for fetching and verifying NVIDIA GPU and NVSwitch
attestation reports. It supports various attestation modes including SPT (Single
Partition Topology), MPT (Multi-Partition Topology), and PPCIE (PCIe
peer-to-peer communication topology).

This project is split into two complementary roles:

1.  **Client**: fetching attestation quotes from GPU and NVSwitch devices.
2.  **Server**: verifying attestation quotes signatures and certificates, and
validating measurements and topology.

Attestation reports are collected using NVIDIA Management Library (NVML) for
GPUs and NVSwitch Configuration and Query (NSCQ) library for NVSwitches.
This means `libnvidia-ml.so` and `libnvidia-nscq.so` must be available in the
library path at runtime.

## Packages

### `client`

This library should be used within the confidential workload to collect GPU or
NVSwitch attestation quotes. The main functions are:

-   `client.GpuQuote(provider client.GpuQuoteProvider, nonce [32]byte) (*pb.GpuAttestationQuote, error)`: Collects GPU attestation quote(s).
-   `client.SwitchQuote(provider client.SwitchQuoteProvider, nonce [32]byte) (*pb.SwitchAttestationQuote, error)`: Collects NVSwitch attestation quote(s).

On Linux, you can use `client.LinuxGpuQuoteProvider{}` and
`client.LinuxSwitchQuoteProvider{}`.

**Example:**

```go
import (
    "crypto/rand"
    "log"
    // ...
)

func main() {
    nonce := [32]byte{}
    if _, err := rand.Read(nonce[:]); err != nil {
        log.Fatalf("failed to generate nonce: %v", err)
    }

    gpuProvider := &client.LinuxGpuQuoteProvider{}
    gpuQuote, err := gpuProvider.CollectGpuEvidence(nonce)
    if err != nil {
      log.Fatalf("Failed to collect GPU evidence: %v", err)
    }
    log.Infof("Got %d GPU reports\n", len(gpuQuote.GpuInfos))

    switchProvider := &client.LinuxSwitchQuoteProvider{}
    switchQuote, err := switchProvider.CollectSwitchEvidence(nonce)
    if err != nil {
      log.Fatalf("Failed to collect SWITCH evidence: %v", err)
    }
    log.Infof("Got %d SWITCH reports\n", len(switchQuote.SwitchInfos))
}
```

### `spt`

This library provides verification for SPT (Single Partition Topology) mode,
used for single GPU verification.

-   `spt.VerifyGpuQuote(ctx context.Context, gpuInfo *pb.GpuInfo, opts spt.Options) (*pb.GpuInfoState, error)`: Verifies and validates a single GPU device attestation.

**Example:**

```go
import (
    "context"
    "log"
    // ...
)

func verifySPT(gpuInfo *pb.GpuInfo, nonce []byte) {
    opts := spt.Options{
        Validation: validate.Options{
            Nonce:           nonce,
            DisableRefCheck: true, // Set to false to enable RIM measurement checks.
        },
        Verification: verify.Options{
            DisableOCSPCheck: true, // Set to false to enable OCSP checks.
            DisableRIMCheck:  true, // Set to false to enable RIM fetching and verification.
            GpuOpts: verify.GPUOpts{
                GPUArch:            gpuInfo.GetGpuArchitecture(),
                MaxCertChainLength: 5, // Adjust based on expected chain length.
            },
        },
    }
    gpuState, err := spt.VerifyGpuQuote(context.Background(), gpuInfo, opts)
    if err != nil {
        log.Fatalf("SPT verification failed for GPU %s: %v", gpuInfo.GetUuid(), err)
    }
    log.Infof("SPT verification result for GPU %s: %+v\n", gpuInfo.GetUuid(), gpuState)
}
```

### `mpt`

This library provides verification for MPT (Multi-Partition Topology) mode, used
for multi-GPU verification without NVSwitches.

-   `mpt.VerifySystemQuotes(ctx context.Context, quote *pb.GpuAttestationQuote, opts mpt.Options) (*pb.GpuQuoteState, error)`: Verifies and validates attestation for multiple GPUs.

**Example:**

```go
import (
    "context"
    "log"
    // ...
)

func verifyMPT(gpuQuote *pb.GpuAttestationQuote, nonce []byte) {
    if len(gpuQuote.GetGpuInfos()) == 0 {
        log.Fatal("No GPU infos to verify")
    }
    opts := mpt.Options{
        Validation: validate.Options{
            Nonce:           nonce,
            DisableRefCheck: true,
        },
        Verification: verify.Options{
            DisableOCSPCheck: true,
            DisableRIMCheck:  true,
            GpuOpts: verify.GPUOpts{
                GPUArch:            gpuQuote.GetGpuInfos()[0].GetGpuArchitecture(),
                MaxCertChainLength: 5,
            },
        },
    }
    quoteState, err := mpt.VerifySystemQuotes(context.Background(), gpuQuote, opts)
    if err != nil {
        log.Fatalf("MPT verification failed: %v", err)
    }
    log.Infof("MPT verification result: %+v\n", quoteState)
}
```

### `ppcie`

This library provides client and server functionalities for PPCIE mode, used in
multi-GPU systems with NVSwitches like NVIDIA HGX platforms.
It supports system pre-checks, quote collection, quote verification, and
topology validation.

**Client-side:**

-   `ppcieclient.Precheck(ctx context.Context,
                            opts *ppcieclient.Options) error`: Performs system-level pre-checks to ensure devices are in the correct mode
    for PPCIE attestation.
-   `ppcieclient.NewAttestation().CollectAllDeviceQuotes(ctx context.Context, opts ppcieclient.CollectOpts) (*pb.GpuAttestationQuote, *pb.SwitchAttestationQuote, error)`: Collects quotes from all GPU and NVSwitch devices.

**Server-side:**

-  `ppcieserver.VerifySystemQuotes(ctx context.Context,
                                    gpuQuote *pb.GpuAttestationQuote,
                                    switchQuote *pb.SwitchAttestationQuote,
                                    opts ppcieserver.Options) (*pb.GpuQuoteState,
                                    *pb.SwitchQuoteState, error)`: Verifies GPU and NVSwitch quotes.
-   `ppcieserver.ValidateSystemTopology(ctx context.Context,
                              gpuAttestationReports []*pb.AttestationReport,
                              switchAttestationReports []*pb.AttestationReport,
                              opts *ppcieserver.Options) error`: Validates topology based on information in attestation reports.

**Example:**

```go
import (
    "context"
    "crypto/rand"
    // ...
)

func attestPPCIE() {
    ctx := context.Background()
    precheckOpts := &ppcieclient.Options{
        ExpectedGpuCount:    8, // Set expected number of GPU devices
        ExpectedSwitchCount: 4, // Set expected number of SWITCH devices
    }
    if err := ppcieclient.Precheck(ctx, precheckOpts); err != nil {
        log.Fatalf("PPCIE pre-checks failed: %v", err)
    }

    nonce := make([]byte, 32)
    if _, err := rand.Read(nonce); err != nil {
        log.Fatalf("failed to generate nonce: %v", err)
    }

    collectOpts := ppcieclient.CollectOpts{Nonce: nonce}
    attest := ppcieclient.NewAttestation()
    gpuQuote, switchQuote, err := attest.CollectAllDeviceQuotes(ctx, collectOpts)
    if err != nil {
        log.Fatalf("Failed to collect quotes: %v", err)
    }

    verifyOpts := ppcieserver.Options{
        ExpectedGpuCount:    8, // Set expected number of GPU devices
        ExpectedSwitchCount: 4, // Set expected number of SWITCH devices
        VerificationOpts: verify.Options{
            DisableOCSPCheck: true,
            DisableRIMCheck:  true,
            GpuOpts: verify.GPUOpts{
                GPUArch:            pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER, // Set expected architecture
                MaxCertChainLength: 5,
            },
            SwitchOpts: verify.SwitchOpts{
                MaxCertChainLength: 5,
            },
        },
        GPUValidationOpts: validate.Options{
            Nonce:           nonce,
            DisableRefCheck: true,
            GpuArch:         pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
            AttestationType: abi.GPU,
        },
        NVSwitchValidationOpts: validate.Options{
            Nonce:           nonce,
            DisableRefCheck: true,
            AttestationType: abi.SWITCH,
        },
    }

    gpuState, switchState, err := ppcieserver.VerifySystemQuotes(ctx, gpuQuote, switchQuote, verifyOpts)
    if err != nil {
        log.Fatalf("PPCIE quote verification failed: %v", err)
    }
    log.Infof("PPCIE GPU states: %+v\n", gpuState)
    log.Infof("PPCIE Switch states: %+v\n", switchState)

    // Optionally validate topology
    var gpuReports []*pb.AttestationReport
    for _, gpuInfo := range gpuQuote.GetGpuInfos() {
        r, err := abi.RawAttestationReportToProto(gpuInfo.GetAttestationReport(), abi.GPU)
        if err != nil {
            log.Fatalf("Failed to parse GPU report: %v", err)
        }
        gpuReports = append(gpuReports, r)
    }
    var switchReports []*pb.AttestationReport
    for _, switchInfo := range switchQuote.GetSwitchInfos() {
        r, err := abi.RawAttestationReportToProto(switchInfo.GetAttestationReport(), abi.SWITCH)
        if err != nil {
            log.Fatalf("Failed to parse Switch report: %v", err)
        }
        switchReports = append(switchReports, r)
    }

    if err := ppcieserver.ValidateSystemTopology(ctx, gpuReports, switchReports, &verifyOpts); err != nil {
        log.Fatalf("PPCIE topology validation failed: %v", err)
    }
    log.Info("PPCIE topology validation successful")
}

```

## License

go-nvattest-tools is released under the Apache 2.0 license.

```
Copyright 2026 Google LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Disclaimer

This is not an officially supported Google product.
