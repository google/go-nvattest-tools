# nvattest

The `nvattest` command-line tool provides a mechanism for device attestation, specifically for NVIDIA GPUs and NVSwitches. Built on top of the `go-nvattest-tools` libraries, `nvattest` offers an interface similar to the NVIDIA C++ Attestation SDK CLI, allowing users to collect evidence from hardware and cryptographically verify it against reference manifests and policies.

## Overview

The CLI follows a subcommand-based interface to separate the retrieval of device evidence from its cryptographic validation:

* `collect-evidence`: Retrieves attestation quotes from live hardware.
* `attest`: Verifies device attestation evidence (either collected live or loaded from a file) against Reference Integrity Manifests (RIMs) and certificate status (OCSP/CRL).
* `version`: Prints the version and build information of the binary.

## Prerequisites

To run `nvattest`, the system must meet the following requirements:

* **Runtime Libraries:** The following libraries must be available in the library path at runtime:
  * **NVIDIA Management Library (NVML)** (`libnvidia-ml.so`) for GPU attestation.
  * **NVSwitch Configuration and Query (NSCQ)** (`libnvidia-nscq.so`) for NVSwitch attestation.
* **Supported Hardware & Minimum Drivers:**
  * **Hopper GPUs (e.g. H100):** Requires NVIDIA Driver **R535 or newer** (e.g., `>= 535.230.02`).
  * **Blackwell GPUs (e.g. B200):** Requires NVIDIA Driver **R570 or newer** (e.g., `>= 570.195.03`).
* **NSCQ Compatibility:** The `libnvidia-nscq` library version must match the major version of the installed NVIDIA driver (e.g., `libnvidia-nscq-535` for R535 driver).
* **Privileges:** Accessing NVML/NSCQ for attestation quote collection on Linux typically requires root privileges (e.g., running with `sudo`).

## Installation

### Pre-built binaries (recommended)

Each [release](https://github.com/google/go-nvattest-tools/releases) ships
ready-to-run `nvattest` binaries for `linux/amd64` and `linux/arm64`, so no Go
toolchain or build environment is needed on the target machine:

```bash
VERSION=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

curl -fsSLO "https://github.com/google/go-nvattest-tools/releases/download/${VERSION}/nvattest_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "https://github.com/google/go-nvattest-tools/releases/download/${VERSION}/SHA256SUMS"

# Verify the download before running it.
sha256sum --ignore-missing -c SHA256SUMS

tar -xzf "nvattest_${VERSION}_linux_${ARCH}.tar.gz"
sudo install -m 0755 "nvattest_${VERSION}_linux_${ARCH}/nvattest" /usr/local/bin/nvattest

nvattest version
```

The released binaries link libxml2 statically, so libxml2 does not have to be
installed. They are built against glibc 2.28, which covers RHEL/Rocky/AlmaLinux
8+, Ubuntu 20.04+ and Debian 11+. The NVIDIA libraries (`libnvidia-ml.so`,
`libnvidia-nscq.so`) are still loaded from the system at runtime, as described
in [Prerequisites](#prerequisites); they are not bundled.

Binaries are published for Linux only, which is the only platform where
attestation evidence can be collected from NVIDIA devices.

### Building from source

To build the `nvattest` binary using standard Go tooling (requires a C compiler
and `libxml2-dev` / `libxml2-devel`, since the RIM schema validation uses cgo
bindings to libxml2):

```bash
go build -o nvattest .
```

To reproduce a release build locally — static libxml2, tarball and checksum in
`dist/` — run the release script on a Linux host of the target architecture:

```bash
./scripts/build-release.sh
```

## Subcommands

### `collect-evidence`

Collects attestation evidence (quotes) from live NVIDIA GPUs or NVSwitches and outputs it in JSON format (protojson).

**Flags:**
* `--device`: Type of device to collect evidence from (`gpu` or `nvswitch`). Default: `gpu`.
* `--nonce`: 32-byte cryptographic nonce in hex string format (64 hex characters).
* `--evidence_file`: Path to save the resulting JSON evidence file. If omitted, the output is printed to `STDOUT`.

**Examples:**

```bash
# Collect GPU evidence with a random nonce and save to file
./nvattest collect-evidence --device=gpu --nonce=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --evidence_file=gpu_evidence.json

# Collect NVSwitch evidence and print to stdout
./nvattest collect-evidence --device=nvswitch
```

### `attest`

Verifies device attestation evidence. It supports both online verification (fetching artifacts dynamically) and offline verification (using cached RIM and OCSP files). It also supports validating live hardware directly or verifying a previously collected evidence file.

**Topology Modes:**
The `attest` command automatically detects the operating topology mode (SPT, MPT, or PPCIe) based on the `OpaqueDataFeatureFlag` embedded inside the attestation report.

**Flags:**
* `--device`: Type of device to attest (`gpu` or `nvswitch`). Default: `gpu`. *(Note: `nvswitch` standalone attestation is currently under development).*
* `--nonce`: 32-byte cryptographic nonce in hex string format, used to verify the freshness of the quote.
* `--evidence_file`: Path to the evidence JSON file (protojson). If omitted, `nvattest` collects evidence from live hardware on the local machine.
* `--rims_file`: Path to cached RIMs (`rims.textproto`). Providing this flag enables offline verification.
* `--rims_ocsp_file`: Path to cached RIM OCSP responses (`rims_ocsp.textproto`). Required if `--rims_file` is provided.
* `--device_ocsp_file`: Path to cached Device OCSP responses (`device_ocsp.textproto`). Required if `--rims_file` is provided.
* `--device_l4_crl_file`: Path to cached L4 Certificate Revocation List (`device_l4_crl.textproto`). Optional for offline verification.

**Examples:**

**1. Live Online Attestation:**
Collects evidence from the local GPU and verifies it online.
```bash
sudo ./nvattest attest --device=gpu
```

**2. Offline Attestation from a File:**
Verifies previously collected evidence against local cache files without inner dependencies or live hardware.
```bash
./nvattest attest \
  --device=gpu \
  --evidence_file=gpu_evidence.json \
  --rims_file=rims.textproto \
  --rims_ocsp_file=rims_ocsp.textproto \
  --device_ocsp_file=device_ocsp.textproto
```

**3. Live Offline Attestation:**
Collects evidence from live hardware and verifies it against local cache files.
```bash
sudo ./nvattest attest \
  --device=gpu \
  --rims_file=rims.textproto \
  --rims_ocsp_file=rims_ocsp.textproto \
  --device_ocsp_file=device_ocsp.textproto
```

### `version`

Prints the version, commit and build date stamped into the binary, plus the Go
version and platform it was built for. Useful when reporting issues against a
pre-built binary.

```bash
./nvattest version
```

## Troubleshooting & Notes

* **Runtime Errors (Missing Libraries)**: If `libnvidia-ml.so` or `libnvidia-nscq.so` cannot be found at runtime, live collection will fail. Ensure these libraries are installed and your `LD_LIBRARY_PATH` is configured correctly. See [Prerequisites](#prerequisites).
* **Permission Denied**: Quote collection will fail if run without sufficient privileges. Ensure you run the tool with `sudo` if required.
* **Cached Artifacts**: When performing offline verification, ensure that the provided RIMs and OCSP responses correspond to the exact VBIOS and Driver versions of the hardware being attested.
