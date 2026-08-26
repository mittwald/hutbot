#!/usr/bin/env bash
# Edit the instance's built-in calendar list, which lives in Vault as the field
# HUTBOT_BUILTIN_CALENDARS of secrets-coabkube/production/hutbot (or .../hutbot-dev).
#
# The list is a JSON array of {"name","title","url"} objects. Its URLs carry feed tokens —
# possession of a published-calendar link *is* read access — so it is secret material and
# lives in Vault rather than in a ConfigMap the way a non-secret feed map would.
#
# Writes back with `vault kv patch` on a KV v2 mount, never a bare `kv put`: a put replaces the
# whole version and would drop the Slack, OpsGenie and employee-list fields beside it. A KV v1
# mount has no patch, so there the other fields are merged back in explicitly — see
# `write_field`.
set -euo pipefail

readonly FIELD=HUTBOT_BUILTIN_CALENDARS

VAULT_MOUNT=${VAULT_MOUNT:-secrets-coabkube/production}

environment=prod
vault_path=${VAULT_PATH:-}
sync=false
show=false

usage() {
  cat <<EOF
Usage: ${0##*/} [--env prod|dev] [--sync] [--show]

Opens the built-in calendar list from Vault in \$EDITOR, validates it, and patches it back.

Options:
  --env prod|dev  Which release's secret to edit: "hutbot" (default) or "hutbot-dev".
  --sync          Afterwards run scripts/sync-secret.sh --restart for that environment.
  --show          Print the current list and exit — it contains the feed tokens.
  -h, --help      Show this help.

Environment overrides: VAULT_MOUNT (${VAULT_MOUNT}), VAULT_PATH, EDITOR.
Vault needs VAULT_ADDR exported and a current login: \`vault login -method=oidc\`.
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
    --sync) sync=true; shift ;;
    --show) show=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

case "$environment" in
  prod|production) release=hutbot ;;
  dev) release=hutbot-dev ;;
  *) echo "error: unknown environment '${environment}' (known: prod, dev)" >&2; exit 2 ;;
esac

vault_path=${vault_path:-${VAULT_MOUNT}/${release}}
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for tool in vault jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: ${tool} not found in PATH" >&2; exit 1; }
done

umask 077
# Under $XDG_RUNTIME_DIR when there is one (tmpfs, user-owned), never under the repository.
workdir=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/hutbot-calendars.XXXXXX")
cleanup() {
  # shred rather than rm: the file held every feed token.
  find "$workdir" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

file="${workdir}/builtin-calendars.json"

if ! vault kv get -format=json "$vault_path" > "${workdir}/vault.json"; then
  echo "error: could not read ${vault_path}; is VAULT_ADDR exported and the login current?" >&2
  echo "       (export VAULT_ADDR=https://vault.m3.services; vault login -method=oidc)" >&2
  exit 1
fi
# `// empty` so an unset field starts as an empty list rather than the four bytes "null".
# KV v2 wraps the fields in .data.data and carries .data.metadata; v1 has them flat under
# .data. Which one this is decides how the edit can be written back.
if jq -e '.data | has("data") and has("metadata")' "${workdir}/vault.json" >/dev/null 2>&1; then
  kv_version=2
  fields_filter='.data.data'
else
  kv_version=1
  fields_filter='.data'
fi

jq -j --arg field "$FIELD" "${fields_filter}[\$field] // empty" "${workdir}/vault.json" > "$file"
[[ -s "$file" ]] || printf '[]\n' > "$file"

write_field() {
  local source=$1
  if [[ "$kv_version" == 2 ]]; then
    # @file keeps the JSON off the command line, and patch keeps the sibling fields.
    vault kv patch "$vault_path" "${FIELD}=@${source}"
    return
  fi
  # KV v1 has no patch, so the sibling fields have to be carried over by hand: they are
  # merged in from the copy read at the start of this edit. Not atomic — a change someone
  # else made to another field in the meantime would be overwritten — and v1 keeps no
  # version history to roll back to, so this is the moment to be sure nobody else is editing.
  echo "==> ${VAULT_MOUNT} is a KV v1 mount: rewriting the secret with the other fields merged in" >&2
  jq --rawfile value "$source" --arg field "$FIELD" \
    "${fields_filter} + {(\$field): \$value}" "${workdir}/vault.json" > "${workdir}/merged.json"
  vault kv put "$vault_path" "@${workdir}/merged.json"
}

if $show; then
  jq . "$file"
  exit 0
fi

validate() {
  local target=$1
  if ! jq -e 'type == "array"' "$target" >/dev/null 2>&1; then
    echo "error: the list must be a JSON array of {\"name\",\"title\",\"url\"} objects" >&2
    return 1
  fi
  if ! jq -e 'all(.[]; (.name  | type == "string" and test("^[a-z0-9][a-z0-9._-]*$"))
                   and (.title | type == "string" and length > 0)
                   and (.url   | type == "string" and startswith("https://")))' \
      "$target" >/dev/null 2>&1; then
    echo "error: every entry needs a slug \"name\" (a-z, 0-9, \`.\`, \`-\`, \`_\`), a non-empty" >&2
    echo "       \"title\" and an https \"url\"" >&2
    return 1
  fi
  if ! jq -e '(map(.name) | length) == (map(.name) | unique | length)' "$target" >/dev/null 2>&1; then
    echo "error: two entries share a name" >&2
    return 1
  fi
}

before=$(jq -S . "$file" 2>/dev/null || cat "$file")
# The file holds every feed token, so it is shredded on exit either way: say so when a write
# fails, rather than leaving someone to wonder whether the edit landed somewhere.
report_and_cleanup() {
  local status=$?
  [[ $status -ne 0 ]] && echo "the edit was NOT saved; re-run and paste it back" >&2
  cleanup
}
trap report_and_cleanup EXIT
"${EDITOR:-vi}" "$file"

if ! validate "$file"; then
  echo "nothing was written; your edit is lost (re-run and paste it back)" >&2
  exit 1
fi
if [[ "$(jq -S . "$file")" == "$before" ]]; then
  echo "unchanged; nothing was written."
  exit 0
fi

echo "==> built-in calendars after this edit:"
jq -r '.[] | "      \(.name)\t\(.title)\t\(.url | sub("^https://";"") | sub("/.*$";""))"' "$file"

write_field "$file"
echo "Vault field ${FIELD} of ${vault_path} updated."

if $sync; then
  exec "${root_dir}/scripts/sync-secret.sh" --env "$environment" --restart
fi
echo "note: the bot reads the list at startup; apply it with:"
echo "      ./scripts/sync-secret.sh --env ${environment} --restart"
