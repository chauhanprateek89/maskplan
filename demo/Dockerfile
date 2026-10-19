# The demo image: maskplan, the synthetic-bank loader, and psql.
# Build context is the repository root (see compose.yaml).
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/maskplan ./cmd/maskplan \
 && CGO_ENABLED=0 go build -o /out/fintech-load ./bench/fintech

FROM alpine:3.20
RUN apk add --no-cache postgresql16-client
COPY --from=build /out/ /usr/local/bin/
COPY testdata/fintech/schema.sql /demo/schema.sql
COPY demo/misconfig.sql demo/load.sh /demo/
WORKDIR /work
ENTRYPOINT ["maskplan"]
