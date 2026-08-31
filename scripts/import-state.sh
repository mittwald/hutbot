#!/usr/bin/env bash
# One-time state migration between hutbot instances — built for moving to another cluster.
#
# Three modes, run against whatever kube-context is current (printed and confirmed, because a
# move by definition touches two clusters and no single expected context fits both):
#
#   --export    Read the state files out of the RUNNING instance into a local directory.
#               Each file is probed on the state volume first and then in the app directory,
#               because versions up to v1.0.x wrote scheduled_replies.json next to the code
#               (ephemeral) rather than onto the volume. Pass --stop to scale the source
#               deployment to zero right after a successful export: the target runs with the
#               same Slack credentials, so a source left running would answer alongside it —
#               and a reminder coming due after the export would be sent by the source and
#               then restored and sent again by the target.
#   --import    Build the out-of-band Secret the chart's `stateImport` reads from that
#               directory. The chart never renders the files itself, so no state value passes
#               through Helm values or the release metadata Helm keeps in the cluster.
#   --cleanup   Delete that Secret again — only after a deploy with the import switched OFF:
#               the import volume is deliberately not `optional`, so a pod restarting with
#               the flag still on would hang at init without the Secret.
#
# The actual write onto the new volume is done by the chart's init container, which never
# overwrites a file that already exists there — the import happens exactly once per file.
#
# The full move:
#   1. old cluster:  ./scripts/import-state.sh --env prod --export --stop
#   2. new cluster:  ./scripts/sync-secret.sh --env prod            # credentials first
#   3. new cluster:  ./scripts/import-state.sh --env prod --import
#   4. new cluster:  STATE_IMPORT_ENABLED=true ./deploy-prod.sh vX.Y.Z
#   5. new cluster:  ./deploy-prod.sh vX.Y.Z                        # flag off again
#   6. new cluster:  ./scripts/import-state.sh --env prod --cleanup
set -euo pipefail

# The closed set of files the bot keeps on the state volume. bot.json is the per-channel
# configuration and the one file a migration is really about; the caches are worth carrying
# so pending reminders and buttons survive the move and the employee data is warm before the
# first fetch. employees-fallback.json is hand-placed, never written by the bot.
readonly KNOWN_FILES=(
  bot.json
  scheduled_replies.json
  button_states.json
  employees.json
  employees-fallback.json
)
readonly REQUIRED_FILES=(bot.json)

NAMESPACE=${NAMESPACE:-mw-internal}
MOUNT_PATH=${MOUNT_PATH:-/data}
# Where old versions kept files that were not on the volume yet (the image's WORKDIR).
APP_PATH=${APP_PATH:-/app}

environment=prod
mode=""
state_dir=""
assume_yes=false
stop_source=false

usage() {
  cat <<EOF
Usage: ${0##*/} [--env prod|dev] (--export [--stop] | --import | --cleanup) [--dir DIR] [-y]

One-time migration of hutbot's state files (configuration and caches) between instances:
--export reads them out of the running instance, --import builds the Secret the chart's
\`stateImport\` init container seeds the new state volume from, --cleanup deletes that
Secret after the import is done and switched off.

Options:
  --env prod|dev  Which release: "hutbot" (default) or "hutbot-dev".
  --export        Copy the state files of the running instance into DIR.
  --stop          After a successful export, scale the source deployment to zero —
                  do this before the target starts, or both answer with the same tokens.
  --import        Create/update the state-import Secret from the files in DIR.
  --cleanup       Delete the state-import Secret.
  --dir DIR       The local state directory (default: ./state-export, gitignored).
  -y, --yes       Skip the kube-context confirmation prompt.
  -h, --help      Show this help.

Environment overrides: NAMESPACE (${NAMESPACE}), DEPLOYMENT, MOUNT_PATH (${MOUNT_PATH}),
APP_PATH (${APP_PATH}), STATE_IMPORT_SECRET (the same override the deploy scripts and the
chart read; SECRET_NAME is accepted as an alias).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      [[ $# -ge 2 ]] || { echo "error: --env needs an argument (prod or dev)" >&2; exit 2; }
      environment="$2"
      shift 2
      ;;
    --env=*) environment="${1#*=}"; shift ;;
    --export|--import|--cleanup)
      [[ -z "$mode" ]] || { echo "error: give exactly one of --export, --import, --cleanup" >&2; exit 2; }
      mode="${1#--}"
      shift
      ;;
    --dir)
      [[ $# -ge 2 ]] || { echo "error: --dir needs a directory" >&2; exit 2; }
      state_dir="$2"
      shift 2
      ;;
    --dir=*) state_dir="${1#*=}"; shift ;;
    --stop) stop_source=true; shift ;;
    -y|--yes) assume_yes=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

[[ -n "$mode" ]] || { echo "error: give one of --export, --import, --cleanup" >&2; usage >&2; exit 2; }
if $stop_source && [[ "$mode" != "export" ]]; then
  echo "error: --stop only makes sense with --export" >&2
  exit 2
fi

case "$environment" in
  prod|production) release=hutbot ;;
  dev) release=hutbot-dev ;;
  *) echo "error: unknown environment '${environment}' (known: prod, dev)" >&2; exit 2 ;;
esac

# STATE_IMPORT_SECRET is the override the deploy scripts and the chart's `stateImport`
# read; honoring it here keeps all three naming the same Secret. SECRET_NAME is an alias.
secret_name=${SECRET_NAME:-${STATE_IMPORT_SECRET:-${release}-state-import}}
deployment=${DEPLOYMENT:-$release}
state_dir=${state_dir:-./state-export}

# The exports hold employee data, and bot.json can carry token-bearing calendar URLs —
# nothing another local account should be able to read.
umask 077

command -v kubectl >/dev/null 2>&1 || { echo "error: kubectl not found in PATH" >&2; exit 1; }

# No EXPECTED_CONTEXT refusal like sync-secret.sh: an export runs against the old cluster and
# an import against the new one, so the context is confirmed instead of pinned.
context=$(kubectl config current-context)
echo "==> mode: --${mode}, release: ${release}, namespace: ${NAMESPACE}, kube-context: ${context}"
if ! $assume_yes; then
  read -r -p "Continue against '${context}'? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

has_file() {
  local needle=$1 file
  shift
  for file in "$@"; do
    [[ "$file" == "$needle" ]] && return 0
  done
  return 1
}

export_state() {
  mkdir -p "$state_dir"
  # The umask covers only what this run creates; a pre-existing directory keeps its mode,
  # so it is tightened explicitly — the files in it are why the umask is set at all.
  chmod og-rwx "$state_dir"
  local file exported=0
  # A re-used directory may hold files from an earlier export — of the other environment,
  # or of a file the instance no longer has. Left in place they would ride into the Secret
  # and resurrect state that no longer exists, so every known output is cleared up front.
  for file in "${KNOWN_FILES[@]}"; do
    if [[ -f "${state_dir}/${file}" ]]; then
      echo "==> clearing previous export ${state_dir}/${file}"
      rm -f "${state_dir}/${file}"
    fi
  done
  for file in "${KNOWN_FILES[@]}"; do
    # The volume first; the app directory covers versions that wrote a cache next to the
    # code. `cat` through exec rather than `kubectl cp`, which needs tar in the image.
    local found=""
    for path in "${MOUNT_PATH}/${file}" "${APP_PATH}/${file}"; do
      if kubectl -n "$NAMESPACE" exec "deploy/${deployment}" -- test -f "$path" 2>/dev/null; then
        found="$path"
        break
      fi
    done
    if [[ -z "$found" ]]; then
      echo "==> ${file}: not present in the running instance; skipping"
      continue
    fi
    kubectl -n "$NAMESPACE" exec "deploy/${deployment}" -- cat "$found" > "${state_dir}/${file}"
    echo "==> exported ${found} ($(wc -c < "${state_dir}/${file}") bytes)"
    exported=$((exported + 1))
  done
  if [[ $exported -eq 0 ]]; then
    echo "error: nothing exported from ${NAMESPACE}/deploy/${deployment}" >&2
    exit 1
  fi
  if $stop_source; then
    # The target answers with the same Slack tokens: a source left running would reply
    # alongside it, and a reminder coming due after this export would be sent here and
    # then again from the restored cache. Stopping is scaling, not deleting — the old
    # release and its volume stay put until someone removes them on purpose.
    kubectl -n "$NAMESPACE" scale "deploy/${deployment}" --replicas=0
    echo "==> scaled ${NAMESPACE}/deploy/${deployment} to 0 replicas"
  else
    echo "==> the source is still running — scale it to zero before the target starts:"
    echo "    kubectl -n ${NAMESPACE} scale deploy/${deployment} --replicas=0"
  fi
  echo "==> ${exported} file(s) in ${state_dir} — now switch the kube-context and run --import"
}

import_state() {
  [[ -d "$state_dir" ]] || { echo "error: ${state_dir} does not exist; run --export first (or pass --dir)" >&2; exit 1; }
  local file args=() imported=()
  for file in "${KNOWN_FILES[@]}"; do
    if [[ ! -f "${state_dir}/${file}" ]]; then
      if has_file "$file" "${REQUIRED_FILES[@]}"; then
        echo "error: ${state_dir}/${file} is missing, and a state import without it is pointless" >&2
        exit 1
      fi
      continue
    fi
    # Every state file is JSON; a truncated export must fail here, not as a bot that starts
    # and then cannot parse its own configuration.
    if ! python3 -m json.tool "${state_dir}/${file}" >/dev/null 2>&1; then
      echo "error: ${state_dir}/${file} is not valid JSON" >&2
      exit 1
    fi
    args+=("--from-file=${file}=${state_dir}/${file}")
    imported+=("$file")
  done
  # Unknown extra files in the directory are ignored on purpose: only files the bot actually
  # reads belong in the Secret, and the init container would copy anything else verbatim.
  kubectl -n "$NAMESPACE" create secret generic "$secret_name" "${args[@]}" \
    --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f -
  echo "==> Secret ${NAMESPACE}/${secret_name} holds: ${imported[*]}"
  echo "==> deploy once with STATE_IMPORT_ENABLED=true; files already on the volume are kept"
  echo "==> afterwards: deploy with the flag off, then run --cleanup"
}

cleanup_state() {
  if ! kubectl -n "$NAMESPACE" get secret "$secret_name" >/dev/null 2>&1; then
    echo "==> Secret ${NAMESPACE}/${secret_name} does not exist; nothing to clean up"
    return 0
  fi
  # The import volume is not `optional`: a pod restarting while the flag is still on would
  # hang at init without this Secret. Refuse until the deployment no longer mounts it.
  if kubectl -n "$NAMESPACE" get deployment "$deployment" -o json 2>/dev/null \
      | grep -q "\"secretName\": \"${secret_name}\""; then
    echo "error: ${NAMESPACE}/${deployment} still mounts ${secret_name}" >&2
    echo "deploy with STATE_IMPORT_ENABLED unset (or false) first, then run --cleanup again" >&2
    exit 1
  fi
  kubectl -n "$NAMESPACE" delete secret "$secret_name"
  echo "==> Secret ${NAMESPACE}/${secret_name} deleted"
}

case "$mode" in
  export) export_state ;;
  import) import_state ;;
  cleanup) cleanup_state ;;
esac
