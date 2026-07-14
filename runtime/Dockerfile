FROM python:3.14-slim@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8080

COPY runtime ./runtime
COPY contracts ./contracts
COPY pyproject.toml ./
COPY requirements-runtime.txt ./

RUN python -m pip install --no-cache-dir -r requirements-runtime.txt \
    && groupadd --system --gid 10001 patchforge \
    && useradd --system --uid 10001 --gid patchforge --home-dir /nonexistent --shell /usr/sbin/nologin patchforge

EXPOSE 8080

USER patchforge

CMD ["python", "-m", "runtime.health_server"]
