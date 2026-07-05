# 8pi Backend — FastAPI + real CLI security tools
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# Install runtime CLI tools used by the Tool Service (real adapters).
# nmap = recon; sqlmap = exploit; gobuster / dirb = dir-brute; wapiti = generic web scanner;
# nikto & wpscan are pulled from their upstream sources (not in Debian bookworm apt).
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      nmap gobuster dirb sqlmap wapiti \
      git perl libnet-ssleay-perl libwhisker2-perl \
      ruby ruby-dev build-essential \
      libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev \
      ca-certificates curl tini && \
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
