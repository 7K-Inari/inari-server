# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/inari-server ./cmd/inari-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/inari-server /inari-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/inari-server"]
