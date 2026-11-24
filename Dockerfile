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

# Non-root user; /scan is where you mount the target.
RUN useradd -m -u 10001 auditor
USER auditor
WORKDIR /scan

ENTRYPOINT ["exhume"]
CMD ["--help"]
