FROM python:3.12-slim

# NER_BACKEND=gliner (default) bundles a local GLiNER model so people, schools, etc. are redacted.
# Build with --build-arg NER_BACKEND=none for a small regex-only image.
ARG NER_BACKEND=gliner
ARG NER_MODEL=urchade/gliner_multi_pii-v1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DB_PATH=/data/vault.db \
    NER_BACKEND=${NER_BACKEND} \
    NER_MODEL=${NER_MODEL} \
    HF_HOME=/opt/hf \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

RUN groupadd --gid 1000 harness \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin harness \
    && mkdir -p /data \
    && chown 1000:1000 /data

WORKDIR /app
COPY pyproject.toml ./

# Dependencies and the model are installed against a stub package first, so code changes do not
# re-download torch or the model. The model is fetched at build time only; at runtime the hub is
# offline, so nothing leaves the container except the sanitized upstream request.
RUN mkdir src && touch src/__init__.py \
    && if [ "$NER_BACKEND" = "gliner" ]; then \
        pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
        && pip install --no-cache-dir ".[ner]" \
        && HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 python -c "from gliner import GLiNER; GLiNER.from_pretrained('${NER_MODEL}')" \
        && chmod -R a+rX /opt/hf; \
    else \
        pip install --no-cache-dir .; \
    fi

COPY src ./src
RUN pip install --no-cache-dir --no-deps --force-reinstall .

USER harness
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
