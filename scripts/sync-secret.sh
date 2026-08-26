#!/usr/bin/env bash
# Sync the out-of-band Kubernetes Secret the hutbot chart consumes via `existingSecret`.
# Source is Vault by default (secrets-coabkube/production/hutbot for the production release,
# .../hutbot-dev for the dev release; override with VAULT_PATH). Every field of the Vault
# secret becomes one key of the Kubernetes Secret, so the deployment receives it as an
# environment variable: SLACK_APP_TOKEN and SLACK_BOT_TOKEN are required, the OpsGenie,
# employee-list and built-in-calendar fields are optional additions.
#
# Nothing here ever passes through Helm: the chart reads this Secret rather than rendering
# one, so no credential lands in a values file or in the release metadata Helm keeps in the
# cluster.
#
# Pass --local to take the values from the current environment instead (`set -a; . ./.env;
# set +a`). Only the keys hutbot actually reads are picked up — NETWORKPOLICY_RULES and the
# other deploy settings in .env are no secrets and have no business in the Secret. A key
# missing there is carried over from the existing Secret, so updating one value never needs
# the others at hand.
#
# The bot reads its environment once at startup: pass --restart (or run
# `kubectl -n mw-internal rollout restart deploy/hutbot`) to apply a change to the running
# deployment. Per-channel configuration lives on the state volume and is untouched here.
set -euo pipefail

# hutbot's secret material is a closed set — unlike mping there is no name pattern to
# discover, and a regex over the environment would sweep .env's deploy settings into the pod.
readonly KNOWN_KEYS=(
  SLACK_APP_TOKEN
  SLACK_BOT_TOKEN
  OPSGENIE_TOKEN
  OPSGENIE_HEARTBEAT_NAME
  EMPLOYEE_LIST_USERNAME
  EMPLOYEE_LIST_PASSWORD
  EMPLOYEE_LIST_MAPPINGS
  HUTBOT_BUILTIN_CALENDARS
)
readonly REQUIRED_KEYS=(SLACK_APP_TOKEN SLACK_BOT_TOKEN)
# `envFrom` puts every value through execve, whose per-variable limit is 128 KiB; past it the
# container fails to start with an opaque E2BIG. The calendar list only ever grows.
readonly WARN_BYTES=32768
readonly FAIL_BYTES=98304

NAMESPACE=${NAMESPACE:-mw-internal}
EXPECTED_CONTEXT=${EXPECTED_CONTEXT:-coabkube-prod}
VAULT_MOUNT=${VAULT_MOUNT:-secrets-coabkube/production}

environment=prod
secret_name=${SECRET_NAME:-}
vault_path=${VAULT_PATH:-}
restart=false
local_mode=false
dry_run=false
allow_drop=false
drop_keys=()

usage() {
  cat <<EOF
Usage: ${0##*/} [--env prod|dev] [--local] [--restart] [--dry-run] [--allow-drop] [--drop KEY]

Rebuilds the Kubernetes Secret the hutbot chart reads through \`existingSecret\`.

Options:
  --env prod|dev  Which release to sync: "hutbot" (default) or "hutbot-dev".
  --local         Read values from the environment instead of Vault.
  --restart       Roll the deployment afterwards so the new values take effect.
  --dry-run       Print the keys that would be written, change nothing.
  --allow-drop    Allow removing keys the live Secret has and this sync does not.
  --drop KEY      Retire one key on purpose (repeatable).
  -h, --help      Show this help.

Environment overrides: NAMESPACE (${NAMESPACE}), SECRET_NAME, DEPLOYMENT,
VAULT_MOUNT (${VAULT_MOUNT}), VAULT_PATH, EXPECTED_CONTEXT (${EXPECTED_CONTEXT}).
Vault needs VAULT_ADDR exported and a current login: \`vault login -method=oidc\`.

A \`vault kv put\` replaces the whole secret version. Use \`vault kv patch\` to change one
field, and \`vault kv rollback -version=N <path>\` to undo one that dropped the others.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      [[ $# -ge 2 ]] || { echo "error: --env needs an argument (prod or dev)" >&2; exit 2; }
      environment="$2"
      shift 2
      ;;
    --env=*)
      environment="${1#*=}"
      shift
      ;;
    --drop)
      [[ $# -ge 2 ]] || { echo "error: --drop needs a key name" >&2; exit 2; }
      drop_keys+=("$2")
      shift 2
      ;;
    --drop=*) drop_keys+=("${1#*=}"); shift ;;
    --local) local_mode=true; shift ;;
    --restart) restart=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    --allow-drop) allow_drop=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

case "$environment" in
  prod|production) release=hutbot ;;
  dev) release=hutbot-dev ;;
  *) echo "error: unknown environment '${environment}' (known: prod, dev)" >&2; exit 2 ;;
esac

secret_name=${secret_name:-$release}
deployment=${DEPLOYMENT:-$release}
if ! $local_mode; then
  vault_path=${vault_path:-${VAULT_MOUNT}/${release}}
fi

command -v kubectl >/dev/null 2>&1 || { echo "error: kubectl not found in PATH" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq not found in PATH" >&2; exit 1; }
if ! $local_mode; then
  command -v vault >/dev/null 2>&1 || { echo "error: vault not found in PATH" >&2; exit 1; }
fi

context=$(kubectl config current-context)
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  echo "refusing to run: current kube-context is '${context}', expected '${EXPECTED_CONTEXT}'" >&2
  echo "(override with EXPECTED_CONTEXT=${context} if this is intentional)" >&2
  exit 1
fi

umask 077
# Never under the repository: a value in the working tree is one `git add -A` from a commit.
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

keys=()

has_key() {
  local needle=$1 key
  shift
  for key in "$@"; do
    [[ "$key" == "$needle" ]] && return 0
  done
  return 1
}

require_variable_name() {
  if [[ ! "$1" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
    echo "error: '${1}' is not a usable environment variable name" >&2
    echo "(the chart injects every Secret key as a variable; the kubelet silently skips the rest)" >&2
    exit 1
  fi
}

read_from_vault() {
  echo "==> reading secret material from Vault: ${vault_path}"
  if ! vault kv get -format=json "$vault_path" > "${workdir}/vault.json"; then
    echo "error: could not read ${vault_path}; is VAULT_ADDR exported and the login current?" >&2
    echo "       (export VAULT_ADDR=https://vault.m3.services; vault login -method=oidc)" >&2
    exit 1
  fi
  local key
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    # Checked before the name is used as a path, not only before it becomes a Secret key.
    require_variable_name "$key"
    if ! has_key "$key" "${KNOWN_KEYS[@]}"; then
      echo "warning: ${key} is not a key hutbot reads — skipping it" >&2
      echo "         (add it to KNOWN_KEYS if that is wrong; envFrom would inject it blindly)" >&2
      continue
    fi
    # -j keeps the value byte-exact: no trailing newline is appended to a token, and the
    # newlines inside HUTBOT_BUILTIN_CALENDARS survive as written. `// empty` matters —
    # `jq -j` renders a JSON null as the four bytes "null", which would pass every
    # non-empty check below and be injected as a literal token.
    jq -j --arg key "$key" '(.data.data // .data)[$key] // empty' \
      "${workdir}/vault.json" > "${workdir}/${key}"
    if [[ ! -s "${workdir}/${key}" ]]; then
      rm -f "${workdir}/${key}"
      if has_key "$key" "${REQUIRED_KEYS[@]}"; then
        echo "error: ${key} is empty in ${vault_path}" >&2
        exit 1
      fi
      # An intentionally empty optional field — OPSGENIE_HEARTBEAT_NAME on dev, so it cannot
      # ping the production heartbeat — asks to be left out, and the bot treats absent and
      # empty alike.
      echo "==> ${key} is empty; leaving it out of the Secret"
      continue
    fi
    keys+=("$key")
  done < <(jq -r '(.data.data // .data) | keys[]' "${workdir}/vault.json")
}

read_from_environment() {
  echo "==> reading secret material from the environment"
  local key
  for key in "${KNOWN_KEYS[@]}"; do
    [[ -n "${!key:-}" ]] || continue
    printf '%s' "${!key}" > "${workdir}/${key}"
    keys+=("$key")
  done
}

carry_over_missing() {
  local key existing
  for key in "${KNOWN_KEYS[@]}"; do
    [[ -f "${workdir}/${key}" ]] && continue
    existing=$(kubectl -n "$NAMESPACE" get secret "$secret_name" \
      -o "jsonpath={.data.${key}}" 2>/dev/null || true)
    if [[ -z "$existing" ]]; then
      if has_key "$key" "${REQUIRED_KEYS[@]}"; then
        echo "error: ${key} is set neither in the environment nor in the existing Secret" >&2
        exit 1
      fi
      continue
    fi
    # A key commented out of .env must not silently retire; --drop is how that is meant.
    echo "==> ${key} not in the environment; carrying it over from ${NAMESPACE}/${secret_name}"
    printf '%s' "$existing" | base64 -d > "${workdir}/${key}"
    keys+=("$key")
  done
}

live_keys() {
  kubectl -n "$NAMESPACE" get secret "$secret_name" -o json 2>/dev/null \
    | jq -r '(.data // {}) | keys[]' 2>/dev/null || true
}

refuse_silent_drops() {
  $allow_drop && return 0
  local key dropped=()
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    has_key "$key" "${keys[@]}" && continue
    if [[ ${#drop_keys[@]} -gt 0 ]] && has_key "$key" "${drop_keys[@]}"; then
      continue
    fi
    dropped+=("$key")
  done < <(live_keys)
  [[ ${#dropped[@]} -eq 0 ]] && return 0
  echo "error: this sync would REMOVE keys that ${NAMESPACE}/${secret_name} has:" >&2
  printf '         %s\n' "${dropped[@]}" >&2
  echo "       a \`vault kv put\` replaces the whole version — use \`vault kv patch\` to change" >&2
  echo "       one field, or \`vault kv rollback -version=N ${vault_path:-<path>}\` to undo one." >&2
  echo "       Pass --allow-drop (or --drop KEY) if the removal is intended." >&2
  exit 1
}

check_prefix() {
  local key=$1 prefix=$2
  [[ -f "${workdir}/${key}" ]] || return 0
  if [[ "$(head -c "${#prefix}" "${workdir}/${key}")" != "$prefix" ]]; then
    # A warning, not an error: Slack has changed token formats before. Swapped tokens
    # authenticate as nothing and would only fail at startup.
    echo "warning: ${key} does not start with '${prefix}' — are the two Slack tokens swapped?" >&2
  fi
}

check_sizes() {
  local key size
  for key in "${keys[@]}"; do
    size=$(wc -c < "${workdir}/${key}")
    if (( size > FAIL_BYTES )); then
      echo "error: ${key} is ${size} bytes; past the exec limit the container will not start" >&2
      exit 1
    fi
    if (( size > WARN_BYTES )); then
      echo "warning: ${key} is ${size} bytes; the per-variable exec limit is 128 KiB" >&2
    fi
  done
}

check_base64_shape() {
  local key
  for key in "${keys[@]}"; do
    # `employee_list.get_env_var` base64-decodes any value that decodes cleanly, so a value
    # that happens to be valid base64 reaches the bot as something else entirely.
    if base64 -d < "${workdir}/${key}" > /dev/null 2>&1; then
      echo "warning: ${key} is valid base64; hutbot decodes such a value on the way in" >&2
    fi
  done
}

check_builtin_calendars() {
  local file="${workdir}/HUTBOT_BUILTIN_CALENDARS"
  [[ -f "$file" ]] || return 0
  if ! jq -e 'type == "array"' "$file" >/dev/null 2>&1; then
    echo "error: HUTBOT_BUILTIN_CALENDARS is not a JSON array" >&2
    exit 1
  fi
  if ! jq -e 'all(.[]; (.name  | type == "string" and test("^[a-z0-9][a-z0-9._-]*$"))
                   and (.title | type == "string" and length > 0)
                   and (.url   | type == "string" and startswith("https://")))' \
      "$file" >/dev/null 2>&1; then
    echo "error: every built-in calendar needs a slug \"name\", a non-empty \"title\"" >&2
    echo "       and an https \"url\"" >&2
    exit 1
  fi
  if ! jq -e '(map(.name) | length) == (map(.name) | unique | length)' "$file" >/dev/null 2>&1; then
    echo "error: two built-in calendars share a name" >&2
    exit 1
  fi
  # A feed host missing from the egress allow-list is dropped without a trace, so name the
  # hosts and let the operator check them. The host is not the secret; the token is.
  echo "==> built-in calendar feed hosts (each needs egress on 443):"
  jq -r '.[] | "      \(.name)\t\(.url | sub("^https://";"") | sub("/.*$";""))"' "$file"
}

if $local_mode; then
  read_from_environment
  carry_over_missing
else
  read_from_vault
fi

if [[ ${#keys[@]} -eq 0 ]]; then
  echo "error: no secret material found — nothing would be written" >&2
  exit 1
fi

for key in "${keys[@]}"; do
  require_variable_name "$key"
done

for key in "${REQUIRED_KEYS[@]}"; do
  if [[ ! -f "${workdir}/${key}" ]]; then
    echo "error: ${key} is missing; the bot cannot connect to Slack without it" >&2
    exit 1
  fi
done

check_prefix SLACK_APP_TOKEN xapp-
check_prefix SLACK_BOT_TOKEN xoxb-
check_sizes
check_base64_shape
check_builtin_calendars
refuse_silent_drops

echo "==> namespace:   ${NAMESPACE}"
echo "==> secret:      ${secret_name}"
echo "==> keys:        ${keys[*]}"
for key in "${keys[@]}"; do
  echo "==>   ${key}: $(wc -c < "${workdir}/${key}") bytes"
done

if $dry_run; then
  echo "dry run: nothing was written."
  exit 0
fi

create_args=()
for key in "${keys[@]}"; do
  # --from-file rather than --from-literal: a token passed as an argument would be visible
  # to every other process on the machine.
  create_args+=(--from-file="${key}=${workdir}/${key}")
done

# Server-side apply: no second copy of the payload in a last-applied annotation, keys removed
# correctly from the first apply on, and a field-manager conflict rather than a silent fight
# if this is ever pointed at a Secret Helm owns. Deliberately no --force-conflicts.
kubectl -n "$NAMESPACE" create secret generic "$secret_name" \
  "${create_args[@]}" --dry-run=client -o yaml \
  | kubectl -n "$NAMESPACE" apply --server-side --field-manager=hutbot-sync-secret -f -

echo "Secret ${NAMESPACE}/${secret_name} synced."
if $restart; then
  kubectl -n "$NAMESPACE" rollout restart "deploy/${deployment}"
  kubectl -n "$NAMESPACE" rollout status "deploy/${deployment}" --timeout=180s
else
  echo "note: the bot reads its environment at startup; use --restart to apply now."
fi
