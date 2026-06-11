# Stage 1: build the Python package
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir hatchling && pip install --no-cache-dir .

# Stage 2: runtime image with Trivy, git, graphviz bundled
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget apt-transport-https gnupg git graphviz ca-certificates \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor > /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/code-guardian /usr/local/bin/code-guardian

WORKDIR /workspace
ENTRYPOINT ["code-guardian"]
CMD ["--help"]
