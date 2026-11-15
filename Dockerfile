FROM golang:alpine AS builder
RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /src
COPY src/ ./
RUN go mod download
RUN go test ./...

FROM builder AS static-builder
RUN apk add --no-cache binutils
RUN CGO_ENABLED=1 go build -tags netgo,osusergo -ldflags '-linkmode external -extldflags "-static"' -o /goatherd-static .
RUN readelf -h /goatherd-static >/dev/null && \
    if readelf -l /goatherd-static | grep -q 'INTERP'; then echo "unexpected dynamic interpreter" >&2; exit 1; fi && \
    if readelf -d /goatherd-static | grep -q '(NEEDED)'; then echo "unexpected shared library dependency" >&2; exit 1; fi

FROM builder AS deployment-builder
RUN apk add --no-cache binutils
RUN go build -o /usr/local/bin/deploybuild ./internal/deploybuild
ENTRYPOINT ["/usr/local/bin/deploybuild"]

FROM scratch AS static-check
COPY --from=static-builder /goatherd-static /goatherd
RUN ["/goatherd", "--help"]

FROM scratch AS static-export
COPY --from=static-check /goatherd /goatherd

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=static-builder /goatherd-static /goatherd
ENTRYPOINT ["/goatherd"]
