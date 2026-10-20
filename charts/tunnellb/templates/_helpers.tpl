{{- define "tunnellb.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/name: tunnellb
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}

{{- define "tunnellb.controllerSelector" -}}
app.kubernetes.io/name: tunnellb
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/component: controller
{{- end -}}

{{- define "tunnellb.clusterRoleName" -}}
{{- $identity := printf "%s/%s" .Release.Namespace .Release.Name -}}
{{- printf "tunnellb-%s-%s" (.Release.Namespace | trunc 40 | trimSuffix "-") ($identity | sha256sum | trunc 8) -}}
{{- end -}}

{{- define "tunnellb.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
