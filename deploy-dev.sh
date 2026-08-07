#!/usr/bin/env bash
# Deploy the hutbot dev instance (release "hutbot-dev") with an explicit image tag.
# Loads .env-dev from the repository root and runs helmfile in the "dev" environment.
set -euo pipefail

readonly HELM_ENV="dev"
readonly ENV_FILE=".env-dev"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: ${0##*/} <image-tag> [helmfile-args...]

Deploys the "${HELM_ENV}" environment using ${ENV_FILE}.
Extra arguments replace the default helmfile command ("sync").

Examples:
  ${0##*/} v1.1.0
  ${0##*/} v1.1.0 diff
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  "")
    echo "error: image tag is required" >&2
    usage >&2
    exit 1
    ;;
esac

image_tag="$1"
shift

if [[ "$image_tag" == "latest" ]]; then
  echo "error: image tags must be pinned to a release, 'latest' is not allowed" >&2
  exit 1
fi

helmfile_args=("$@")
if [[ ${#helmfile_args[@]} -eq 0 ]]; then
  helmfile_args=(sync)
fi

if ! command -v helmfile >/dev/null 2>&1; then
  echo "error: helmfile not found in PATH" >&2
  exit 1
fi

env_path="${root_dir}/${ENV_FILE}"
if [[ ! -f "$env_path" ]]; then
  echo "error: ${env_path} not found" >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "$env_path"
set +a

export IMAGE_TAG="$image_tag"

echo "==> environment: ${HELM_ENV}"
echo "==> env file:    ${ENV_FILE}"
echo "==> image tag:   ${IMAGE_TAG}"
echo "==> namespace:   ${NAMESPACE:-mw-internal}"

cd "$root_dir"
exec helmfile -e "$HELM_ENV" "${helmfile_args[@]}"
