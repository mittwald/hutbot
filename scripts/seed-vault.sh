#!/usr/bin/env bash
# One-shot: seed a hutbot Vault path from the env file that used to hold the credentials.
#
# This is the *only* place a `vault kv put` is right: a put replaces the whole secret version,
# so it is how an empty path is filled and nothing else. Every later change is a
# `vault kv patch` (scripts/edit-calendars.sh does that for the calendar list), which leaves
# the sibling fields alone. The script therefore refuses to run against a path that already
# has fields unless --force is given.
#
# Values never reach a command line: the env file is sourced into this process and the payload
# is built with jq's `env` builtin, then handed to Vault as @file and shredded.
set -euo pipefail

readonly SECRET_KEYS=(
  SLACK_APP_TOKEN
  SLACK_BOT_TOKEN
  OPSGENIE_TOKEN
  OPSGENIE_HEARTBEAT_NAME
  EMPLOYEE_LIST_USERNAME
  EMPLOYEE_LIST_PASSWORD
  EMPLOYEE_LIST_MAPPINGS
)
readonly REQUIRED_KEYS=(SLACK_APP_TOKEN SLACK_BOT_TOKEN)

VAULT_MOUNT=${VAULT_MOUNT:-secrets-coabkube/production}

environment=prod
env_file=""
calendars_file=""
vault_path=${VAULT_PATH:-}
force=false
dry_run=false
sync=false

usage() {
  cat <<EOF
Usage: ${0##*/} [--env prod|dev] [--env-file PATH] [--calendars FILE] [--dry-run] [--force] [--sync]

Fills an empty hutbot Vault path from an env file, so the credentials stop travelling through
Helm values. Run it once per environment; use \`vault kv patch\` for changes afterwards.

Options:
  --env prod|dev    Which path to seed: .../hutbot (default) or .../hutbot-dev.
  --env-file PATH   Env file to read (default: .env for prod, .env-dev for dev).
  --calendars FILE  Also seed HUTBOT_BUILTIN_CALENDARS from this JSON file.
  --dry-run         Print the field names and byte lengths, write nothing.
  --force           Overwrite a path that already has fields (a put replaces every field).
  --sync            Afterwards run scripts/sync-secret.sh for that environment.
  -h, --help        Show this help.

Environment overrides: VAULT_MOUNT (${VAULT_MOUNT}), VAULT_PATH.
Vault needs VAULT_ADDR exported and a current login: \`vault login -method=oidc\`.

Fields seeded: ${SECRET_KEYS[*]}
Required: ${REQUIRED_KEYS[*]}. Everything else in the env file — NETWORKPOLICY_RULES,
HOST_ALIASES, PERSISTENCE_*, HUTBOT_TIMEZONE — is deploy configuration and stays there.
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
    --env-file)
      [[ $# -ge 2 ]] || { echo "error: --env-file needs a path" >&2; exit 2; }
      env_file="$2"
      shift 2
      ;;
    --env-file=*) env_file="${1#*=}"; shift ;;
    --calendars)
      [[ $# -ge 2 ]] || { echo "error: --calendars needs a path" >&2; exit 2; }
      calendars_file="$2"
      shift 2
      ;;
    --calendars=*) calendars_file="${1#*=}"; shift ;;
    --dry-run) dry_run=true; shift ;;
    --force) force=true; shift ;;
    --sync) sync=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

case "$environment" in
  prod|production) release=hutbot; default_env_file=.env ;;
  dev) release=hutbot-dev; default_env_file=.env-dev ;;
  *) echo "error: unknown environment '${environment}' (known: prod, dev)" >&2; exit 2 ;;
esac

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file=${env_file:-${root_dir}/${default_env_file}}
vault_path=${vault_path:-${VAULT_MOUNT}/${release}}

for tool in vault jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: ${tool} not found in PATH" >&2; exit 1; }
done

if [[ ! -f "$env_file" ]]; then
  echo "error: ${env_file} not found" >&2
  echo "pass --env-file PATH, or seed the fields by hand with \`vault kv put\`" >&2
  exit 1
fi

umask 077
# tmpfs and user-owned where there is one, and never inside the repository.
workdir=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/hutbot-seed.XXXXXX")
cleanup() {
  find "$workdir" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

payload="${workdir}/payload.json"

# A put replaces the whole version, so a populated path would lose whatever this run does not
# carry — the very mistake the sync script's drop guard exists to catch downstream.
if vault kv get -format=json "$vault_path" > "${workdir}/existing.json" 2>/dev/null; then
  existing_fields=$(jq -r '((.data.data // .data) | keys) | join(", ")' "${workdir}/existing.json")
  if [[ -n "$existing_fields" && "$existing_fields" != "null" ]]; then
    if ! $force; then
      echo "error: ${vault_path} already has fields: ${existing_fields}" >&2
      echo "       seeding replaces the whole version. To change one field use:" >&2
      echo "         vault kv patch ${vault_path} KEY=…" >&2
      echo "       or, for the calendar list: ./scripts/edit-calendars.sh --env ${environment}" >&2
      echo "       Pass --force only if replacing every field is what you mean." >&2
      exit 1
    fi
    echo "warning: --force replaces every field of ${vault_path}: ${existing_fields}" >&2
  fi
fi

echo "==> reading ${env_file}"
set -a
# shellcheck source=/dev/null
source "$env_file"
set +a

# jq's `env` builtin rather than --arg: a value passed as an argument would be readable in
# /proc/<pid>/cmdline while jq runs. `with_entries` drops what the env file does not set, so a
# missing optional field is left unset instead of stored as an empty string.
jq -n '$ENV | {SLACK_APP_TOKEN, SLACK_BOT_TOKEN, OPSGENIE_TOKEN, OPSGENIE_HEARTBEAT_NAME,
               EMPLOYEE_LIST_USERNAME, EMPLOYEE_LIST_PASSWORD, EMPLOYEE_LIST_MAPPINGS}
        | with_entries(select(.value != null and .value != ""))' > "$payload"

if [[ -n "$calendars_file" ]]; then
  [[ -f "$calendars_file" ]] || { echo "error: ${calendars_file} not found" >&2; exit 1; }
  # The same checks sync-secret.sh runs, so a truncated paste fails here rather than at startup.
  if ! jq -e 'type == "array"
              and all(.[]; (.name  | type == "string" and test("^[a-z0-9][a-z0-9._-]*$"))
                       and (.title | type == "string" and length > 0)
                       and (.url   | type == "string" and startswith("https://")))
              and ((map(.name) | length) == (map(.name) | unique | length))' \
      "$calendars_file" >/dev/null 2>&1; then
    echo "error: ${calendars_file} must be a JSON array of {\"name\",\"title\",\"url\"} objects" >&2
    echo "       with slug names (unique), non-empty titles and https URLs" >&2
    exit 1
  fi
  jq --rawfile calendars "$calendars_file" \
    '. + {HUTBOT_BUILTIN_CALENDARS: $calendars}' "$payload" > "${payload}.next"
  mv "${payload}.next" "$payload"
fi

for key in "${REQUIRED_KEYS[@]}"; do
  if ! jq -e --arg key "$key" 'has($key)' "$payload" >/dev/null; then
    echo "error: ${key} is not set in ${env_file}; the bot cannot connect to Slack without it" >&2
    exit 1
  fi
done

echo "==> vault path:  ${vault_path}"
echo "==> fields:"
# Names and byte lengths only — never a value.
jq -r 'to_entries[] | "      \(.key): \(.value | length) bytes"' "$payload"

if $dry_run; then
  echo "dry run: nothing was written."
  exit 0
fi

# @file keeps every value off the command line.
vault kv put "$vault_path" "@${payload}"
echo "Vault path ${vault_path} seeded."
echo "note: from here on use \`vault kv patch\` — a put would replace every field."

if $sync; then
  exec "${root_dir}/scripts/sync-secret.sh" --env "$environment"
fi
echo "next: ./scripts/sync-secret.sh --env ${environment} --dry-run"
