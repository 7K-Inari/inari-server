FROM golang:{{ .Values.GoVersion }} AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/service .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/service /service
EXPOSE {{ .Values.Port }}
USER nonroot
ENTRYPOINT ["/service"]
