FROM python:3.11-alpine AS builder
ENV ENGINE=owl_dns


WORKDIR /engine

RUN apk add --no-cache gcc musl-dev libffi-dev

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"


COPY base_engine /base_engine
COPY owl_dns/requirements.txt /engine

COPY owl_dns/metadatas.json.sample /engine/metadatas.json

COPY owl_dns/. /engine

ADD https://github.com/Patrowl/Sublist3r.git /app/Sublist3r
RUN pip install --no-cache-dir -r /app/Sublist3r/requirements.txt
RUN pip install -r /engine/requirements.txt

# Final image
FROM python:3.11-alpine

WORKDIR /engine

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/Sublist3r /engine/external-libs/Sublist3r
COPY --from=builder /engine /engine

# RUN apk add --no-cache libffi

CMD ["celery", "-A", "tasks", "worker", "--queues=engine-OwlDNS", "--loglevel=info", "--concurrency=2", "--prefetch-multiplier=1"]