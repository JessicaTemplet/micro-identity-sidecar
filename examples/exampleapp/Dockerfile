FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY examples ./examples
RUN CGO_ENABLED=0 go build -o /out/exampleapp ./examples/exampleapp

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/exampleapp /exampleapp
ENTRYPOINT ["/exampleapp"]
