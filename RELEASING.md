# Releasing

This document describes how pre-built `nvattest` binaries are produced and
published. It is meant for maintainers; users should download binaries from the
[releases page](https://github.com/google/go-nvattest-tools/releases) as
described in [cmd/nvattest/README.md](cmd/nvattest/README.md).

## Cutting a release

1. Make sure `main` is green and contains everything the release should carry.
2. Tag the commit and push the tag:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. Pushing a `v*` tag triggers
   [`.github/workflows/release.yml`](.github/workflows/release.yml), which
   builds the binaries, runs the libxml2-sensitive tests against the exact
   libxml2 that gets linked in, and creates the GitHub release with generated
   release notes.
4. Review the generated notes on the release page and publish any edits.

The workflow can also be re-run for an existing tag from the Actions tab
("Release" → "Run workflow" → tag), which re-uploads the artifacts with
`--clobber`.

## What gets published

For each of `linux/amd64` and `linux/arm64`:

* `nvattest_<tag>_linux_<arch>.tar.gz`, containing the `nvattest` binary,
  `LICENSE` and the CLI `README.md`.
* A single `SHA256SUMS` file covering both tarballs.

Only Linux binaries are published: `client` (and therefore the CLI) is
implemented for Linux only, since NVML and NSCQ are the sources of attestation
evidence.

## How the binaries are built

[`scripts/build-release.sh`](scripts/build-release.sh) does the actual work and
can be run locally on a Linux host of the target architecture:

```bash
./scripts/build-release.sh            # writes dist/nvattest_<version>_linux_<arch>.tar.gz
VERSION=v0.1.0 ./scripts/build-release.sh
```

Two constraints shape the build:

* **libxml2 is linked statically.** `server/rim` validates RIM XML with cgo
  bindings to libxml2, so a plain `go build` produces a binary that needs
  `libxml2.so` on the target machine. The script builds a minimal libxml2
  (no zlib/lzma/icu/python/http) as a static archive and links that instead.
* **glibc stays dynamically linked.** `nvattest` `dlopen()`s
  `libnvidia-ml.so` and `libnvidia-nscq.so` at runtime, which a fully static
  glibc binary cannot do — so a `-static` build would break
  `collect-evidence` and live attestation. To keep the binaries portable
  despite the dynamic glibc, the release workflow builds inside an
  `almalinux:8` container (glibc 2.28); the script prints the resulting minimum
  glibc version and fails if libxml2 ended up dynamically linked.

Cross-compiling is not possible for the same reason cgo is needed, so the
amd64 binary is built on a `ubuntu-24.04` runner and the arm64 binary on a
`ubuntu-24.04-arm` runner. If GitHub-hosted arm64 runners are unavailable for
the repository, remove the `arm64` entry from the workflow matrix.

## Upgrading the bundled libxml2

The version is pinned, with its checksum, at the top of
`scripts/build-release.sh`. To move to a new version:

```bash
LIBXML2_VERSION=2.14.7 LIBXML2_SHA256=<sha256 of the .tar.xz> ./scripts/build-release.sh
```

Once it builds and `go test ./server/rim/... ./cmd/nvattest/...` passes against
it, update `LIBXML2_VERSION`, `DEFAULT_LIBXML2_VERSION` and
`DEFAULT_LIBXML2_SHA256` in the script. Schema validation behaviour does change
between libxml2 releases, which is why the release workflow runs those tests
against the statically linked build before publishing.

## Version stamping

The build stamps `main.version`, `main.commit` and `main.buildDate` via
`-ldflags`, and `nvattest version` prints them. Binaries built with a plain
`go build` print the module version and VCS revision that the Go toolchain
embeds instead.
