FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --upgrade pip && pip install .
RUN useradd -m appuser && chown -R appuser /app
USER appuser
# Runs to completion; SIGTERM drains in-flight probes gracefully.
ENTRYPOINT ["recon-orchestrator"]
CMD ["run"]
