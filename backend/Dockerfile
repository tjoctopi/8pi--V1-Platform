# 8pi Backend — FastAPI + real CLI security tools
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# Install runtime CLI tools used by the Tool Service (real adapters).
# nmap = recon; sqlmap = exploit; dirb = dir-brute; gobuster from its GitHub
# release (not in Debian bookworm); wapiti dropped (not packaged) — the Tool
# Service falls back to sim for any missing binary (TOOL_MODE=auto).
# nikto & wpscan are pulled from upstream sources; nikto needs perl JSON +
# XML::Writer (libjson-perl, libxml-writer-perl) to run without erroring.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      nmap dirb sqlmap \
      git perl libnet-ssleay-perl libwhisker2-perl libjson-perl libxml-writer-perl \
      ruby ruby-dev build-essential \
      libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev \
      ca-certificates curl tini && \
    curl -fsSL https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz -o /tmp/gb.tgz && \
    tar -xzf /tmp/gb.tgz -C /usr/local/bin gobuster && \
    chmod +x /usr/local/bin/gobuster && rm -f /tmp/gb.tgz && \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    gem install --no-document wpscan && \
    apt-get purge -y --auto-remove ruby-dev build-essential \
      libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev git && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

EXPOSE 8001
ENV PYTHONPATH=/app/backend
WORKDIR /app/backend

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8001/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]
