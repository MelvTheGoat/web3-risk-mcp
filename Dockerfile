# Build stage: install the project and its dependencies with uv.
FROM python:3.12-slim-bookworm AS builder

RUN pip install --no-cache-dir "uv==0.8.17"

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Install dependencies first, so this layer is cached when only code changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev


# Runtime stage: a small image with only what is needed to run.
FROM python:3.12-slim-bookworm

# Run as a normal user, not root.
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=builder --chown=app:app /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

USER app
EXPOSE 8000

# Default: streamable HTTP on port 8000.
# For stdio instead: docker run -i --rm --env-file .env web3-risk-mcp --transport stdio
ENTRYPOINT ["web3-risk-mcp"]
CMD ["--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
