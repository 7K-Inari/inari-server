# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.27@sha256:23fe8075c2e428136326703a2c63203f0c57595d8400eedbe06a29cab53055e8 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inari-server ./cmd/inari-server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inari-kubeproxy ./cmd/inari-kubeproxy

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/inari-server /inari-server
COPY --from=build /src/templates /templates
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/inari-server"]

# Kubectl gateway data plane (plan §7.2). Build with:
#   docker build --target kubeproxy -t ghcr.io/7k-inari/inari-kubeproxy .
# Published by the inari-release-bundle chart workflow (follow-up); the
# release pipeline in this repo ships only the inari-server image today.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS kubeproxy
COPY --from=build /out/inari-kubeproxy /inari-kubeproxy
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/inari-kubeproxy"]
