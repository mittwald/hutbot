#!/usr/bin/env bash
# Deploy the hutbot production instance (release "hutbot") with an explicit image tag.
# Loads .env from the repository root and runs helmfile in the "default" environment.
set -euo pipefail

readonly HELM_ENV="default"
readonly ENV_FILE=".env"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: ${0##*/} [-y] <image-tag> [helmfile-args...]

Deploys the "${HELM_ENV}" (production) environment using ${ENV_FILE}.
Extra arguments replace the default helmfile command ("sync").

Options:
  -y, --yes   Skip the confirmation prompt.

Examples:
  ${0##*/} v1.1.0
  ${0##*/} v1.1.0 diff
  ${0##*/} -y v1.1.0
EOF
}

assume_yes=0
if [[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]]; then
  assume_yes=1
  shift
fi

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

if [[ "${image_tag,,}" == "latest" || "${image_tag,,}" == "main" ]]; then
  echo "error: image tags must be pinned to a release, '${image_tag}' is not allowed" >&2
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "error: kubectl not found in PATH" >&2
  exit 1
fi

# The credentials live in a Secret this chart only reads (scripts/sync-secret.sh writes it).
# Checked before Helm runs: `strategy: Recreate` takes the old pod down first, so a Secret
# that is missing a key would leave nothing running at all.
namespace="${NAMESPACE:-mw-internal}"
release="hutbot"
secret_name="${HUTBOT_EXISTING_SECRET:-$release}"
export HUTBOT_EXISTING_SECRET="$secret_name"

if ! kubectl -n "$namespace" get secret "$secret_name" >/dev/null 2>&1; then
  echo "error: Kubernetes Secret ${namespace}/${secret_name} not found" >&2
  echo "sync it first: ./scripts/sync-secret.sh --env prod" >&2
  exit 1
fi
for key in SLACK_APP_TOKEN SLACK_BOT_TOKEN; do
  if [[ -z "$(kubectl -n "$namespace" get secret "$secret_name" -o "jsonpath={.data.${key}}" 2>/dev/null)" ]]; then
    echo "error: ${namespace}/${secret_name} has no ${key}" >&2
    echo "a \`vault kv put\` replaces the whole version; re-run: ./scripts/sync-secret.sh --env prod" >&2
    exit 1
  fi
done

# A Deployment created with the default RollingUpdate strategy carries a spec.strategy.rollingUpdate
# block the API server filled in. Server-side apply merges `type: Recreate` on top but leaves that
# block alone — it belongs to no applier — and validation then refuses the whole object with
# "spec.strategy.rollingUpdate: Forbidden: may not be specified when strategy `type` is 'Recreate'".
# Clearing it is idempotent, and strategy is no part of the pod template, so nothing restarts here.
strategy=$(kubectl -n "$namespace" get deployment "$release" \
  -o "jsonpath={.spec.strategy.type}" 2>/dev/null || true)
if [[ -n "$strategy" && "$strategy" != "Recreate" ]]; then
  echo "==> ${namespace}/${release} still has strategy ${strategy}; clearing its rollingUpdate block"
  kubectl -n "$namespace" patch deployment "$release" --type=merge \
    -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}'
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
if [[ -f "$env_path" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$env_path"
  set +a
else
  # Only deploy settings live here now (NETWORKPOLICY_RULES, HOST_ALIASES, PERSISTENCE_*,
  # HUTBOT_TIMEZONE, HUTBOT_DEFAULT_DATETIME_LOCALE) — the credentials come from the Secret.
  echo "warning: ${env_path} not found; deploying with the chart defaults" >&2
fi

export IMAGE_TAG="$image_tag"

echo "==> environment: ${HELM_ENV} (production)"
echo "==> env file:    ${ENV_FILE}"
echo "==> image tag:   ${IMAGE_TAG}"
echo "==> namespace:   ${namespace}"
echo "==> secret:      ${secret_name}"
echo "==> command:     helmfile -e ${HELM_ENV} ${helmfile_args[*]}"

if [[ "$assume_yes" -ne 1 && "${helmfile_args[0]}" != "diff" ]]; then
  read -r -p "Deploy to PRODUCTION? [y/N] " answer
  if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
    echo "aborted"
    exit 1
  fi
fi

cd "$root_dir"
exec helmfile -e "$HELM_ENV" "${helmfile_args[@]}"
