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
