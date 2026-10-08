# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inari-server ./cmd/inari-server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inari-kubeproxy ./cmd/inari-kubeproxy

# Kubectl gateway data plane (plan §7.2, ADR-0014). Published by this repo's
# release pipeline (publish.yml build-kubeproxy job, same version tags as the
# server image):
#   docker build --target kubeproxy -t ghcr.io/7k-inari/inari-kubeproxy .
# The matching chart block (values kubeproxy.*, replicaCount pinned to 1)
# lives in the inari-release-bundle chart.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS kubeproxy
COPY --from=build /out/inari-kubeproxy /inari-kubeproxy
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/inari-kubeproxy"]

# Control plane server image. Every image build MUST select its stage
# explicitly (`target: server` / `target: kubeproxy`) — this stage is kept
# last only as defense-in-depth so a target-less build still produces the
# server image. CI (ci.yaml image job) asserts both entrypoints.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS server
COPY --from=build /out/inari-server /inari-server
COPY --from=build /src/templates /templates
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/inari-server"]
