FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY requirements.txt /opt/opencti-connector-deaddrop-hunter/requirements.txt
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir -r /opt/opencti-connector-deaddrop-hunter/requirements.txt && \
    apk del git build-base

COPY src /opt/opencti-connector-deaddrop-hunter
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh && \
    adduser -D -H connector && chown -R connector /opt/opencti-connector-deaddrop-hunter
USER connector

ENTRYPOINT ["/entrypoint.sh"]
