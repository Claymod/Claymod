# Build stage: compiles the claymod binary (control server + agent + CLI).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/claymod ./cmd/claymod

# Runtime stage: alpine so `claymod exec` (shell ops) work for manual poking.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl openssl && mkdir -p /var/lib/claymod
COPY --from=build /out/claymod /usr/local/bin/claymod
# The /shared volume carries tokens and the CA fingerprint between the
# services (control -> host) during the enrollment flow.
VOLUME ["/shared"]
ENTRYPOINT ["claymod"]
