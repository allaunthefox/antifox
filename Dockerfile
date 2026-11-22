# syntax=docker/dockerfile:1
#
# Runtime image (nothing is compiled inside the image): install only common tools, and drop in the **prebuilt Linux single binary**.
# The binary is cross-compiled by the CI binaries job (pure Go, no QEMU) and placed by target architecture in
# dist/<TARGETARCH>/antifox in the build context. That way, multi-arch builds only need arm64 to emulate the apt layer,
# instead of emulating the Next/Go build, which is much faster.
#
# When building the image manually locally, prepare the binary first:
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/antifox ./cmd/antifox
#   docker build -t antifox:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add or remove as needed).
# Install Node 20.x from NodeSource: bookworm's apt nodejs is 18, and Playwright requires >=20.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Preinstall Playwright MCP/CLI + Chromium so the in-container browser MCP works out of the box.
# Note: the previous layer cleared the apt lists, and `--with-deps` needs apt to install Chromium's system dependencies,
# so this layer runs apt-get update first to rebuild the lists; otherwise playwright install fails with exit 100.
RUN apt-get update \
    && npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# Report generation depends on python-docx (called as a subprocess, report_builder.py, when the Go side renders .docx files)
RUN pip install --no-cache-dir python-docx
WORKDIR /app
# Prebuilt binary for the matching architecture (dist/amd64/antifox or dist/arm64/antifox)
COPY dist/${TARGETARCH}/antifox /app/antifox
RUN chmod +x /app/antifox
COPY skills/ /app/skills/
# data/ (SQLite + jwt.key) persistence point
VOLUME ["/app/data"]
EXPOSE 8787
ENTRYPOINT ["/app/antifox"]
CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]
