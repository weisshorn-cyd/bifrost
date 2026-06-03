FROM --platform=$BUILDPLATFORM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/bifrost-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bifrost-server /bifrost-server
EXPOSE 5353/udp 8053/tcp
ENTRYPOINT ["/bifrost-server"]
