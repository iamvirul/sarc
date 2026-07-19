# Build stage
FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG BUILT_BY=docker

WORKDIR /build

# Cache module downloads before copying source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X main.version=${VERSION} \
      -X main.commit=${COMMIT} \
      -X main.builtBy=${BUILT_BY}" \
    -o /sarc \
    ./cmd/sarc

# Runtime stage: distroless for minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /sarc /sarc

ENTRYPOINT ["/sarc"]
