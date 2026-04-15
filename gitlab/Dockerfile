FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        ripgrep \
        golang \
    && rm -rf /var/lib/apt/lists/*

# Optional grep accelerator for large repositories.
RUN GOBIN=/usr/local/bin go install github.com/google/codesearch/cmd/cindex@latest \
    && GOBIN=/usr/local/bin go install github.com/google/codesearch/cmd/csearch@latest

WORKDIR /workspace
