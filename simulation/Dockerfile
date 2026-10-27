# Build stage: compiles the claymod binary and the simulation certgen tool.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY simulation/certgen/ simulation/certgen/
RUN CGO_ENABLED=0 go build -o /out/claymod ./cmd/claymod \
 && CGO_ENABLED=0 go build -o /out/certgen ./simulation/certgen

# Runtime stage: alpine so `claymod exec` (shell ops) work for manual poking.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && mkdir -p /var/lib/claymod
COPY --from=build /out/claymod /usr/local/bin/claymod
COPY --from=build /out/certgen /usr/local/bin/certgen
# The /certs volume is shared: certgen writes it, agent and control read it.
VOLUME ["/certs"]
ENTRYPOINT ["claymod"]
