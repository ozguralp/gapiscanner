FROM python:3.12-slim

WORKDIR /opt/scanner
COPY pyproject.toml README.md LICENSE ./
COPY gapiscanner_core ./gapiscanner_core
RUN python -m pip install --no-cache-dir .

RUN mkdir -p /work /data && chown 10001:10001 /work /data
ENV GAPISCANNER_DATA_DIR=/data
USER 10001:10001
WORKDIR /work

ENTRYPOINT ["gapiscanner"]
