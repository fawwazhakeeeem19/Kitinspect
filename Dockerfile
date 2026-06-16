FROM golang:1.21-alpine AS builder

WORKDIR /build
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=1.0.0
ARG GIT_COMMIT=docker
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -w -s" \
    -trimpath \
    -o kitinspect \
    ./cmd/kitinspect/
FROM python:3.11-slim AS python-deps

WORKDIR /python
COPY python/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true
FROM debian:bookworm-slim

LABEL maintainer="KitInspect Team"
LABEL description="KitInspect - Professional APK Security Analysis"
LABEL version="1.0.0"
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
    tzdata \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -r kitinspect && useradd -r -g kitinspect -s /bin/false kitinspect
COPY --from=builder /build/kitinspect /usr/local/bin/kitinspect
COPY --from=python-deps /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY python/ /opt/kitinspect/python/
RUN mkdir -p /data/reports /data/uploads && \
    chown -R kitinspect:kitinspect /data /opt/kitinspect
ENV PYTHONPATH=/opt/kitinspect/python
ENV OUTPUT_DIR=/data/reports
ENV TZ=UTC

WORKDIR /data

USER kitinspect

ENTRYPOINT ["kitinspect"]
CMD ["--help"]
