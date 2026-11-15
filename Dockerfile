FROM golang:alpine AS builder
RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /src
COPY src/ ./
RUN go mod download
RUN go test ./...
RUN go build -o /goatherd .

FROM alpine:latest
RUN apk add --no-cache libpcap
COPY --from=builder /goatherd /goatherd
ENTRYPOINT ["/goatherd"]
