# {{ .Values.repoName }}

Team {{ .Values.team }} GitOps repository.

## Layout

- `apps/` — Application manifests
- `clusters/` — Cluster-scoped overlays
- `policies/` — Policy and constraint manifests
- `root-application.yaml` — App-of-apps root Application
- `project.yaml` — ArgoCD AppProject for team isolation

## Sync Model

This repository is synced by the tenant-local ArgoCD via the root Application.
Changes committed to the `{{ .Values.baseBranch }}` branch are automatically applied.
