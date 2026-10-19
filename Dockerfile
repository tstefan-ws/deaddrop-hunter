# deaddrop-hunter: hunter image (runs hunt -> export -> build_site in a loop).
# Used by docker-compose.yml together with an nginx container that serves site/.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HUNT_INTERVAL_SECONDS=21600

WORKDIR /app

# Install the package first for better layer caching.
COPY pyproject.toml ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

COPY config ./config
COPY web ./web
COPY scripts ./scripts
RUN sed -i 's/\r$//' scripts/*.sh && chmod +x scripts/*.sh \
    && useradd --create-home --uid 1000 hunter \
    && mkdir -p data site logs && chown -R hunter:hunter /app

USER hunter

# data/ and site/ are volumes (see docker-compose.yml) so results survive restarts.
VOLUME ["/app/data", "/app/site"]

CMD ["bash", "-c", "while true; do scripts/run_hunt.sh || echo \"run failed (exit $?)\"; echo \"sleeping ${HUNT_INTERVAL_SECONDS}s\"; sleep \"${HUNT_INTERVAL_SECONDS}\"; done"]
