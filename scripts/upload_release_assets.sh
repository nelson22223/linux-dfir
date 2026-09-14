#!/usr/bin/env bash
# Upload cross-compiled detector binaries to the ddei-rootkit release.
# Run from any machine with GitHub access:
#   GH_TOKEN=<token> bash scripts/upload_release_assets.sh v0.1.0 dist/
set -euo pipefail

TAG="${1:?usage: upload_release_assets.sh <tag> <dist-dir>}"
DIST="${2:-dist}"
REPO="nelson22223/linux-dfir"

RELEASE_ID=$(curl -sf -H "Authorization: token ${GH_TOKEN}" \
  "https://api.github.com/repos/${REPO}/releases/tags/${TAG}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

for f in "${DIST}"/ddei-rootkit-detector-linux-*; do
  [ -f "$f" ] || continue
  name=$(basename "$f")
  echo "uploading ${name} -> release ${RELEASE_ID}"
  curl -sf -X POST \
    -H "Authorization: token ${GH_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${f}" \
    "https://uploads.github.com/repos/${REPO}/releases/${RELEASE_ID}/assets?name=${name}"
  echo
done
echo "done."
