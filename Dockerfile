FROM golang:alpine as builder
COPY . /goatherd

WORKDIR /goatherd
RUN go mod download
RUN go test
RUN go build

FROM alpine:latest
COPY --from=builder /goatherd/goatherd /goatherd
ENTRYPOINT /goatherd
