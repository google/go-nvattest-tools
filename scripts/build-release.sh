#!/usr/bin/env bash
#
# Builds a redistributable `nvattest` binary and packages it as a tarball.
#
# The binary links libxml2 statically so that it runs on machines that do not
# have libxml2 installed, while glibc stays dynamically linked: `nvattest`
# dlopen()s libnvidia-ml.so / libnvidia-nscq.so at runtime, which a fully
# static binary cannot do.
#
# Usage:
#   scripts/build-release.sh
#
# Environment:
#   VERSION           Version string stamped into the binary.
#                     Default: `git describe --tags --always --dirty`.
#   OUTPUT_DIR        Directory for the tarball and the raw binary. Default: dist.
#   LIBXML2_VERSION   libxml2 release to build and link against. Default: 2.14.6.
#   LIBXML2_SHA256    Expected sha256 of the libxml2 tarball. Defaults to the
#                     checksum of the default version; set it when overriding
#                     LIBXML2_VERSION, or to "skip" to disable the check.
#   BUILD_DIR         Scratch directory for the libxml2 build. Default: OUTPUT_DIR/.build.
#
# Cross-compiling is not supported: cgo needs a C toolchain for the target, so
# build linux/amd64 on an amd64 host and linux/arm64 on an arm64 host (or in a
# container on those hosts). See .github/workflows/release.yml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo devel)}"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/dist}"
BUILD_DIR="${BUILD_DIR:-${OUTPUT_DIR}/.build}"
LIBXML2_VERSION="${LIBXML2_VERSION:-2.14.6}"
DEFAULT_LIBXML2_VERSION="2.14.6"
DEFAULT_LIBXML2_SHA256="7ce458a0affeb83f0b55f1f4f9e0e55735dbfc1a9de124ee86fb4a66b597203a"
LIBXML2_SHA256="${LIBXML2_SHA256:-}"
if [[ -z "${LIBXML2_SHA256}" ]]; then
  if [[ "${LIBXML2_VERSION}" == "${DEFAULT_LIBXML2_VERSION}" ]]; then
    LIBXML2_SHA256="${DEFAULT_LIBXML2_SHA256}"
  else
    echo "error: LIBXML2_SHA256 must be set when overriding LIBXML2_VERSION (or set it to 'skip')" >&2
    exit 1
  fi
fi

GOOS="$(go env GOOS)"
GOARCH="$(go env GOARCH)"
if [[ "${GOOS}" != "linux" ]]; then
  echo "error: nvattest only builds for linux, but GOOS=${GOOS}" >&2
  echo "       run this script on a Linux host or inside a Linux container." >&2
  exit 1
fi

PREFIX="${BUILD_DIR}/libxml2-${LIBXML2_VERSION}-${GOARCH}"
NAME="nvattest_${VERSION}_${GOOS}_${GOARCH}"

mkdir -p "${OUTPUT_DIR}" "${BUILD_DIR}"

# --- 1. Build a static libxml2 ------------------------------------------------
#
# Only the archive (libxml2.a) is produced, so `-lxml2` resolves statically.
# The optional compression/network/python bindings are disabled: the RIM schema
# validation in server/rim only needs the XML parser and the XSD validator.
if [[ ! -f "${PREFIX}/lib/libxml2.a" ]]; then
  echo "==> Building libxml2 ${LIBXML2_VERSION} (static) for ${GOARCH}"
  tarball="${BUILD_DIR}/libxml2-${LIBXML2_VERSION}.tar.xz"
  if [[ ! -f "${tarball}" ]]; then
    curl -fsSL -o "${tarball}" \
      "https://download.gnome.org/sources/libxml2/${LIBXML2_VERSION%.*}/libxml2-${LIBXML2_VERSION}.tar.xz"
  fi
  if [[ "${LIBXML2_SHA256}" != "skip" ]]; then
    echo "${LIBXML2_SHA256}  ${tarball}" | sha256sum -c -
  fi

  src="${BUILD_DIR}/libxml2-${LIBXML2_VERSION}"
  rm -rf "${src}"
  tar -xf "${tarball}" -C "${BUILD_DIR}"
  (
    cd "${src}"
    ./configure \
      --prefix="${PREFIX}" \
      --disable-shared \
      --enable-static \
      --without-python \
      --without-icu \
      --without-lzma \
      --without-zlib \
      --without-http
    make -j"$(nproc)"
    make install
  )
fi

# --- 2. Build nvattest --------------------------------------------------------
echo "==> Building nvattest ${VERSION} for ${GOOS}/${GOARCH}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
# SOURCE_DATE_EPOCH keeps the stamp reproducible when the caller provides one.
BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH:-$(date -u +%s)}" +%Y-%m-%dT%H:%M:%SZ)"

BIN="${OUTPUT_DIR}/${NAME}/nvattest"
mkdir -p "$(dirname "${BIN}")"

export CGO_ENABLED=1
export PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig"
# pkg-config omits Libs.private for a non-static query, but a static libxml2.a
# still needs libm.
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -lm"

go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o "${BIN}" \
  ./cmd/nvattest

# --- 3. Sanity-check the result ----------------------------------------------
echo "==> Verifying ${BIN}"
if ldd "${BIN}" | grep -qi 'libxml2'; then
  echo "error: binary is dynamically linked against libxml2:" >&2
  ldd "${BIN}" >&2
  exit 1
fi
echo "    shared library dependencies:"
ldd "${BIN}" | sed 's/^/      /'
if command -v objdump >/dev/null 2>&1; then
  glibc_min="$(objdump -T "${BIN}" 2>/dev/null |
    grep -o 'GLIBC_[0-9.]*' | sort -u -V | tail -1 || true)"
  [[ -n "${glibc_min}" ]] && echo "    minimum glibc: ${glibc_min}"
fi
"${BIN}" version

# --- 4. Package ---------------------------------------------------------------
echo "==> Packaging ${NAME}.tar.gz"
cp LICENSE "${OUTPUT_DIR}/${NAME}/LICENSE"
cp cmd/nvattest/README.md "${OUTPUT_DIR}/${NAME}/README.md"
tar -czf "${OUTPUT_DIR}/${NAME}.tar.gz" -C "${OUTPUT_DIR}" "${NAME}"
(cd "${OUTPUT_DIR}" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256")

echo "==> Done: ${OUTPUT_DIR}/${NAME}.tar.gz"
