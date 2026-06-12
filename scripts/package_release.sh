#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-v1}"
OUT_DIR="${OUT_DIR:-releases}"
PKG_NAME="linux-dfir-collector-${VERSION}"
SKILL_NAME="linux-dfir-analyzer-skill-${VERSION}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${ROOT_DIR}/${OUT_DIR}/${PKG_NAME}"

cd "${ROOT_DIR}"

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    printf 'required file missing: %s\n' "${path}" >&2
    exit 1
  fi
}

rm -rf "${PKG_DIR}" "${ROOT_DIR}/${OUT_DIR}/${PKG_NAME}.tar.gz" "${ROOT_DIR}/${OUT_DIR}/${PKG_NAME}.tar.gz.sha256"
mkdir -p "${PKG_DIR}/bin" "${PKG_DIR}/profiles"

make linux

for arch in amd64 arm64 386; do
  require_file "dist/dfir-collector-linux-${arch}"
  cp "dist/dfir-collector-linux-${arch}" "${PKG_DIR}/bin/"
done

cp -R profiles/. "${PKG_DIR}/profiles/"
cp README.md "${PKG_DIR}/README_PROJECT.md"
cp -f "${ROOT_DIR}/scripts/release-launcher.sh" "${PKG_DIR}/dfir-collector"
chmod 0755 "${PKG_DIR}/dfir-collector"

if [[ -f "payload/tmbrfix" ]]; then
  mkdir -p "${PKG_DIR}/payload"
  cp "payload/tmbrfix" "${PKG_DIR}/payload/tmbrfix"
  (cd "${PKG_DIR}/payload" && COPYFILE_DISABLE=1 tar -cf payload.tar tmbrfix)
else
  printf 'payload/tmbrfix not found; tmbrfix scanner plugin will be absent from this package\n' >&2
fi

cat > "${PKG_DIR}/VERSION" <<EOF_VERSION
${PKG_NAME}
commit: $(git rev-parse --short HEAD)
build_date: $(date -u +%Y-%m-%d)
default_profile: deep
default_output: ./dfir_YYYYMMDDHHMMSS + ./dfir_YYYYMMDDHHMMSS.tar.gz
default_scan: none
launcher: ./dfir-collector auto-detects Linux CPU architecture
EOF_VERSION

(cd "${PKG_DIR}" && find . -type f -not -name CHECKSUMS.sha256 -print0 | sort -z | xargs -0 shasum -a 256 > CHECKSUMS.sha256)
(cd "${ROOT_DIR}/${OUT_DIR}" && COPYFILE_DISABLE=1 tar --exclude='.DS_Store' -czf "${PKG_NAME}.tar.gz" "${PKG_NAME}")
(cd "${ROOT_DIR}/${OUT_DIR}" && shasum -a 256 "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")

rm -rf "${ROOT_DIR}/${OUT_DIR}/${SKILL_NAME}.tar.gz" "${ROOT_DIR}/${OUT_DIR}/${SKILL_NAME}.tar.gz.sha256"
(cd "${ROOT_DIR}/skills" && COPYFILE_DISABLE=1 tar --exclude='.DS_Store' -czf "${ROOT_DIR}/${OUT_DIR}/${SKILL_NAME}.tar.gz" linux-dfir-analyzer)
(cd "${ROOT_DIR}/${OUT_DIR}" && shasum -a 256 "${SKILL_NAME}.tar.gz" > "${SKILL_NAME}.tar.gz.sha256")

printf 'created %s\n' "${ROOT_DIR}/${OUT_DIR}/${PKG_NAME}.tar.gz"
printf 'created %s\n' "${ROOT_DIR}/${OUT_DIR}/${SKILL_NAME}.tar.gz"
