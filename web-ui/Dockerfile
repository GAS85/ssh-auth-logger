FROM node:22-alpine

ARG STATS_URL=http://127.0.0.1:8080/stats
ARG LOG_FILE_PATH=/var/log/ssh-auth-logger.log
ARG MY_LOCATION=CH
ARG DASHBOARD_PORT=8081

ARG VERSION=dev
ARG VCS_REF=dev
ARG BUILD_DATE=unknown

ENV DASHBOARD_PORT=$DASHBOARD_PORT

LABEL maintainer="GAS85" \
      org.opencontainers.image.title="ssh-auth-logger" \
      org.opencontainers.image.description="A low/zero interaction ssh authentication logging honeypot" \
      org.opencontainers.image.source="https://github.com/GAS85/ssh-auth-logger/web-ui" \
      org.opencontainers.image.url="https://hub.docker.com/r/GAS85/ssh-auth-logger@latest-webui" \
      org.opencontainers.image.documentation="https://github.com/GAS85/ssh-auth-logger/web-ui/README.md" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION

WORKDIR /web-ui
COPY . .

# Run Tests
RUN node --test test.js

HEALTHCHECK \
    --interval=5m \
    --timeout=5s \
    --retries=1 \
    --start-period=5s \
    CMD ["sh", "-c", "wget --spider http://127.0.0.1:$DASHBOARD_PORT"]

CMD node server.js