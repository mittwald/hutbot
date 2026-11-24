{{/*
The Secret is managed out of band (scripts/sync-secret.sh, sourced from Vault) and read-only
here: no credential passes through Helm values, or through the release metadata Helm keeps in
the cluster. There is deliberately no fallback that templates a Secret from values — that
would put the tokens back into `helm template` and `helmfile diff` output.
*/}}
{{- define "hutbot.secretName" -}}
{{- required "existingSecret is required: sync it from Vault first (make sync-secret)" .Values.existingSecret -}}
{{- end -}}

{{/*
Where the built-in calendar list is projected inside the container. One Secret key, one file.
*/}}
{{- define "hutbot.builtinCalendarsFile" -}}
{{- printf "%s/%s" (trimSuffix "/" (clean .Values.builtinCalendars.mountPath)) .Values.builtinCalendars.fileName -}}
{{- end -}}

{{/*
The Secret the one-time state import reads its files from. Like the credential Secret it is
managed out of band (scripts/import-state.sh) and only referenced here, so no state file
passes through Helm values or the release metadata.
*/}}
{{- define "hutbot.stateImportSecretName" -}}
{{- .Values.stateImport.secretName | default (printf "%s-state-import" .Release.Name) -}}
{{- end -}}

{{/*
True when the calendar list should be mounted: asked for, and there is a Secret to read it
from. Kept in one place because the volume, the mount and the env pointer must agree.
*/}}
{{- define "hutbot.mountBuiltinCalendars" -}}
{{- if and .Values.builtinCalendars.mountFile .Values.existingSecret -}}
true
{{- end -}}
{{- end -}}

{{/*
The team mappings as the `key=Team,key=Team` strings hutbot reads. The env format has no
escaping, so a comma anywhere, or an `=` in a key, would silently split an entry: refuse those
here, at render time, rather than mis-map at runtime.
*/}}
{{- define "hutbot.teamMappingEntry" -}}
{{- $key := .key | default "" | toString | trim -}}
{{- $team := .team | default "" | toString | trim -}}
{{- if or (not $key) (not $team) -}}
{{- fail (printf "%s: every entry needs a non-empty key and team (got %q=%q)" .what $key $team) -}}
{{- end -}}
{{- if or (contains "," $key) (contains "=" $key) (contains "," $team) -}}
{{- fail (printf "%s: %q=%q contains a comma, or an = in the key, which the env format cannot carry" .what $key $team) -}}
{{- end -}}
{{- printf "%s=%s" $key $team -}}
{{- end -}}

{{- define "hutbot.departmentTeamMappings" -}}
{{- $entries := list -}}
{{- range $department, $team := . -}}
{{- $entries = append $entries (include "hutbot.teamMappingEntry" (dict "key" $department "team" $team "what" "employeeDirectory.departmentTeamMappings")) -}}
{{- end -}}
{{- join "," $entries -}}
{{- end -}}

{{- define "hutbot.usergroupTeamMappings" -}}
{{- $entries := list -}}
{{- range . -}}
{{- $entries = append $entries (include "hutbot.teamMappingEntry" (dict "key" .part "team" .team "what" "employeeDirectory.usergroupTeamMappings")) -}}
{{- end -}}
{{- join "," $entries -}}
{{- end -}}
