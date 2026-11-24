# Exhume — secrets discovery & verification
# Build:  docker build -t exhume .
# Run:    docker run --rm -v "$PWD:/scan" exhume /scan --verify
FROM python:3.12-slim AS base

# System deps:
#  - git            : full Git-history scanning
#  - tesseract-ocr  : OCR of images (on by default)
#  - libmagic1      : robust file typing for some extractors
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        git tesseract-ocr libmagic1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/exhume
COPY pyproject.toml README.md ./
COPY exhume ./exhume

# Install with all optional extras (documents, archives, SMB/S3, OCR, YAML rules).
RUN pip install --no-cache-dir ".[full]"

# Local AI runtime (prebuilt CPU wheel). If none exists for this platform the build still succeeds and
# Exhume simply tries again (or falls back to Ollama) at run time.
RUN pip install --no-cache-dir --only-binary=llama-cpp-python llama-cpp-python \
        --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu \
 || echo "llama-cpp-python wheel unavailable: AI filter will install itself on first run"

# Non-root user; /scan is where you mount the target. The AI model (~2.1 GB) is downloaded on first
# run into ~/.cache/exhume: mount a volume there to keep it between runs:
#   docker run --rm -v exhume-cache:/home/auditor/.cache/exhume -v "$PWD:/scan" exhume /scan
RUN useradd -m -u 10001 auditor \
 && mkdir -p /home/auditor/.cache/exhume && chown -R auditor /home/auditor/.cache
USER auditor
WORKDIR /scan

ENTRYPOINT ["exhume"]
CMD ["--help"]
