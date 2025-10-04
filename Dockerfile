FROM golang:1.25 AS builder

COPY . /app
WORKDIR /app

RUN go get ./...
RUN go generate ./...
RUN go test ./...

RUN CGO_ENABLED=0 GOARCH=${GOARCH} GOOS=${GOOS} go build -ldflags '-extldflags "-static"' .

FROM debian:stable

WORKDIR /app
COPY --from=builder /app/burn-after-reading .

EXPOSE 8080

ENTRYPOINT ["./burn-after-reading"]
