FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/sidecar ./cmd/sidecar

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/sidecar /sidecar
# Loopback by default; override SIDECAR_LISTEN_ADDR only if you understand
# the trust-boundary implications of exposing this beyond localhost/pod.
ENV SIDECAR_LISTEN_ADDR=0.0.0.0:9091
EXPOSE 9091
ENTRYPOINT ["/sidecar"]
