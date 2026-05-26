FROM python:3.14-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

COPY runtime ./runtime
COPY contracts ./contracts
COPY pyproject.toml ./

EXPOSE 8080

CMD ["python", "-m", "runtime.health_server"]

