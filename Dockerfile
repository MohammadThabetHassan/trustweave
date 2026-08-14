# syntax=docker/dockerfile:1
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

LABEL org.opencontainers.image.title="TrustWeave" \
      org.opencontainers.image.description="Local deterministic security evidence for declared agent trust boundaries" \
      org.opencontainers.image.version="0.2.0" \
      org.opencontainers.image.source="https://github.com/MohammadThabetHassan/trustweave"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir --no-deps . \
    && addgroup --system --gid 10001 trustweave \
    && adduser --system --uid 10001 --ingroup trustweave trustweave

USER trustweave

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD trustweave --help >/dev/null || exit 1

ENTRYPOINT ["trustweave"]
CMD ["--help"]
