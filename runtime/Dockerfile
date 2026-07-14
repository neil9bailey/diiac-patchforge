FROM python:3.14-slim@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

COPY runtime ./runtime
COPY contracts ./contracts
COPY pyproject.toml ./
COPY requirements-runtime.txt ./

RUN python -m pip install --no-cache-dir -r requirements-runtime.txt

EXPOSE 8080

CMD ["python", "-m", "runtime.health_server"]
