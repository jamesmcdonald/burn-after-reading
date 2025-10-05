FROM node:22 AS nodebuild

WORKDIR /webbuild

COPY package.json package-lock.json .
RUN npm install

COPY assets ./assets
COPY templates ./templates
RUN npm run build

FROM golang:1.25 AS builder

WORKDIR /app
COPY . .
COPY --from=nodebuild /webbuild/web ./web

RUN go get ./...
RUN go generate ./...
RUN go test ./...

RUN CGO_ENABLED=0 go build .

FROM cgr.dev/chainguard/wolfi-base

WORKDIR /app
COPY --from=builder /app/burn-after-reading .

EXPOSE 8080

ENTRYPOINT ["./burn-after-reading"]
