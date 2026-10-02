FROM golang:{{ .Values.goVersion }} AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/service .

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/service /service
EXPOSE {{ .Values.port }}
USER nonroot
ENTRYPOINT ["/service"]
