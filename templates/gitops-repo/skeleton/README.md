# {{ .Values.repoName }}

Team {{ .Values.team }} GitOps repository.

## Layout

- `apps/` — Application manifests
- `clusters/` — Cluster-scoped overlays
- `policies/` — Policy and constraint manifests
- `project.yaml` — ArgoCD AppProject for team isolation

The app-of-apps root Application that syncs this repository is owned by the
platform: it is committed into the org's baseline repo
(`gitops-repos/<name>/root-app.yaml`) and registered with the tenant ArgoCD
by the provisioning run — it is intentionally not duplicated here.

## Sync Model

This repository is synced by the tenant-local ArgoCD via the root Application.
Changes committed to the `{{ .Values.baseBranch }}` branch are automatically applied.
