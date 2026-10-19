FROM python:3.14-slim

LABEL org.opencontainers.image.title="mimamori" \
      org.opencontainers.image.description="Self-hosted drive health monitor: the server with the web page, history and alerts. The hosts run the small image mimamori-agent." \
      org.opencontainers.image.source="https://github.com/Pascal2108/mimamori" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# Log lines appear in `docker logs` / Portainer immediately
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
# Exact versions with their hashes, generated from requirements.in with pip-compile: a package
# that was changed on its way here is refused.
# pip is not needed once the packages are in, and its own bundled libraries only add
# attack surface and findings in vulnerability scans
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
 && pip uninstall -y pip \
 && rm -rf "$(python -c 'import ensurepip, os; print(os.path.dirname(ensurepip.__file__))')"

# agent.py holds the encrypted agent protocol that the server shares with the agents
COPY app.py agent.py LICENSE ./
COPY templates/ templates/
COPY static/ static/

# The version shown on the page, set by the build workflow
ARG VERSION=dev
ENV APP_VERSION=$VERSION

RUN useradd -r -u 1000 app \
 && mkdir /data \
 && chown app:app /data \
 && chmod 700 /data
USER app

EXPOSE 8000
HEALTHCHECK CMD python app.py health || exit 1

# One worker: the background jobs (offline agents, weekly report) must run exactly once.
# No control socket: it is not used, and the read-only container has nowhere to put it.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "--threads", "8", "--timeout", "60", "--no-control-socket", "app:create_app()"]
