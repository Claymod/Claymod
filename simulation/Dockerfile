# Build stage: compiles the control binary and the small static agent.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/claymod ./cmd/claymod
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/claymod-agent ./cmd/claymod-agent

# Runtime stage: alpine so `claymod exec` (shell ops) work for manual poking.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl openssl && mkdir -p /var/lib/claymod
COPY --from=build /out/claymod /usr/local/bin/claymod
# The agent binary is NOT preinstalled on agent hosts — it is downloaded
# from the control server during bootstrap (see scripts/enroll-entry.sh).
# It lives in /opt so the air-gap flow can be exercised from scratch.
COPY --from=build /out/claymod-agent /opt/claymod-agent-src
VOLUME ["/shared"]
ENTRYPOINT ["claymod"]
