FROM golang:alpine AS builder

WORKDIR /app

COPY . .

RUN go install . 

FROM alpine:latest

ARG VERSION=dev
ARG VCS_REF=dev
ARG BUILD_DATE=unknown
ARG LABEL_MAINTAINER="Justin Azoff <justin.azoff@gmail.com>"
ARG LABEL_IMAGE_SOURCE="JustinAzoff/ssh-auth-logger"
ARG LABEL_IMAGE_URL="justinazoff/ssh-auth-logger"

LABEL maintainer="$LABEL_MAINTAINER" \
      org.opencontainers.image.title="ssh-auth-logger" \
      org.opencontainers.image.description="A low/zero interaction ssh authentication logging honeypot" \
      org.opencontainers.image.source="https://github.com/$LABEL_IMAGE_SOURCE" \
      org.opencontainers.image.url="https://hub.docker.com/r/$LABEL_IMAGE_URL" \
      org.opencontainers.image.documentation="https://github.com/$LABEL_IMAGE_SOURCE#" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION

ENV VERSION=$VERSION
ENV USER=nobody
ENV SSHD_BIND=:2222
ENV TELNET_BIND=:2323
# This is needed to enable aes128-cbc and 3des old insecure ciphers support
ENV GODEBUG="sshserverinsecurecbc=1"
# This needs special Test. Run build and force dropbear profile:
#
# docker run -t -i --rm -p 2222:2222 -e FORCE_SSH_PROFILE=dropbear ssh-auth-logger:latest
#
# Connect to it with old aes128-cbc:
# ssh -v -c aes128-cbc root@127.0.0.1 -p 2222 2>&1 | grep "aes128-cbc"

COPY --from=builder /go/bin/ssh-auth-logger /go/bin/ssh-auth-logger

RUN touch /var/log/ssh-auth-logger.log && \
    chown $USER /var/log/ssh-auth-logger.log && \
    chmod 644 /var/log/ssh-auth-logger.log

USER $USER

EXPOSE 2222 2323

HEALTHCHECK \
    --interval=5m \
    --timeout=5s \
    --retries=1 \
    --start-period=5s \
    CMD ["sh", "-c", "pgrep ssh-auth-logger && test -s /var/log/ssh-auth-logger.log || exit 1"]

CMD ["/bin/sh", "-c", "test -f /var/log/ssh-auth-logger.log || { echo 'Creating log file...' && touch /var/log/ssh-auth-logger.log; }; /go/bin/ssh-auth-logger 2>&1 | tee -a /var/log/ssh-auth-logger.log"]