{{/*
Expand the name of the chart.
*/}}
{{- define "inari-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "inari-server.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "inari-server.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "inari-server.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "inari-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "inari-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: inari-server
{{- end }}

{{/*
Name of the service account to use.
*/}}
{{- define "inari-server.serviceAccountName" -}}
{{- include "inari-server.fullname" . }}
{{- end }}

{{/*
OIDC issuer URL: explicit value, or derived from the Keycloak base URL+realm.
*/}}
{{- define "inari-server.oidcIssuerUrl" -}}
{{- if .Values.oidc.issuerUrl }}
{{- .Values.oidc.issuerUrl }}
{{- else }}
{{- printf "%s/realms/%s" .Values.keycloak.baseUrl .Values.keycloak.realm }}
{{- end }}
{{- end }}
