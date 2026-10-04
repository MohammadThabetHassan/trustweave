# syntax=docker/dockerfile:1
# The environment the paper's measurements ran in: the package and its research scripts, OPA
# and the Kyverno CLI at the versions the artifacts record, the Cedar CLI's experimental build
# and cvc5 for the SymCC check (each binary checked against the release's published SHA-256),
# the Cedar engine's Python binding and the Z3 solver.
# reproduce/README.md says what to run in it, what each run writes and how long it takes.
#
#   docker build -f reproduce/Dockerfile -t trustweave-reproduce .
#   docker run --rm trustweave-reproduce verify
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl xz-utils unzip \
    && rm -rf /var/lib/apt/lists/*

ARG OPA_VERSION=1.20.2
ARG OPA_SHA256=69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f
ARG KYVERNO_VERSION=1.19.1
ARG KYVERNO_SHA256=b38228f367fc0fdc2b08f4c83ea50ac5f16c60ff8d62d76a66157c33c47b70ae
RUN curl -fsSL -o /usr/local/bin/opa \
        "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
    && echo "${OPA_SHA256}  /usr/local/bin/opa" | sha256sum -c - \
    && chmod +x /usr/local/bin/opa \
    && curl -fsSL -o /tmp/kyverno.tar.gz \
        "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/kyverno-cli_v${KYVERNO_VERSION}_linux_x86_64.tar.gz" \
    && echo "${KYVERNO_SHA256}  /tmp/kyverno.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/kyverno.tar.gz -C /usr/local/bin kyverno \
    && rm /tmp/kyverno.tar.gz

ARG CEDAR_CLI_VERSION=4.12.0
ARG CEDAR_CLI_SHA256=bb991fe1fc25b24d1a1cd1b78266950e8d33015eb818acabe297365bc4905392
ARG CVC5_VERSION=1.3.1
ARG CVC5_SHA256=1a1cda20d2df4938fa4944a69f33ddc9172e319ece0eed0aa09c4d7abede3ed1
RUN curl -fsSL -o /tmp/cedar.tar.xz \
        "https://github.com/cedar-policy/cedar/releases/download/cedar-policy-cli-v${CEDAR_CLI_VERSION}/cedar-policy-cli-experimental-x86_64-unknown-linux-gnu.tar.xz" \
    && echo "${CEDAR_CLI_SHA256}  /tmp/cedar.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/cedar.tar.xz -C /tmp \
    && install -m 0755 /tmp/cedar-policy-cli-experimental-x86_64-unknown-linux-gnu/cedar /usr/local/bin/cedar \
    && curl -fsSL -o /tmp/cvc5.zip \
        "https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VERSION}/cvc5-Linux-x86_64-static.zip" \
    && echo "${CVC5_SHA256}  /tmp/cvc5.zip" | sha256sum -c - \
    && unzip -q /tmp/cvc5.zip -d /tmp \
    && install -m 0755 /tmp/cvc5-Linux-x86_64-static/bin/cvc5 /usr/local/bin/cvc5 \
    && rm -rf /tmp/cedar.tar.xz /tmp/cedar-policy-cli-* /tmp/cvc5.zip /tmp/cvc5-Linux-*

WORKDIR /work
COPY . .
RUN python -m pip install --no-cache-dir -e ".[dev]" "cedarpy==4.12.1" \
    && chmod +x reproduce/run.sh

ENTRYPOINT ["reproduce/run.sh"]
CMD ["verify"]
