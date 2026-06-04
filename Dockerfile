# syntax=docker/dockerfile:1
#
# Multi-stage build → distroless static runtime.
# modernc.org/sqlite is pure-Go, so the binary is fully static (CGO_ENABLED=0)
# and runs on the smallest non-root distroless base.

# ---- build stage ----
FROM golang:1.26 AS build
WORKDIR /src

# Cache module downloads on an isolated layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X github.com/inovacc/sentinel/cmd.version=${VERSION}" \
    -o /out/sentinel .

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/sentinel /usr/local/bin/sentinel

# Bootstrap (Syncthing-style pairing) and mTLS data-plane ports.
EXPOSE 7399 7400

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["serve"]
