FROM golang:alpine AS builder

ARG VERSION=dev
ARG VCS_REF=__none__
ARG BUILD_DATE=unknown

WORKDIR /app

COPY . .

# Write version and build into the binary file.
# '__none__' shall be longer than 8 symbols
RUN sed -e "s/appVersion = \"dev\"/appVersion = \"$VERSION\"/" \
        -e "s/\"__none__\"/\"$VCS_REF\"/" \
        -i main.go

RUN go install . 

FROM alpine:latest

ARG VERSION=dev
ARG VCS_REF=dev
ARG BUILD_DATE=unknown

LABEL maintainer="GAS85 <v4adezwcd@mozmail.com>" \
      org.opencontainers.image.title="ssh-auth-logger" \
      org.opencontainers.image.description="A low/zero interaction ssh and telnet authentication logging honeypot with web UI. Can report IP to AbuseIPDB, OTX, dshield, blocklist and spamhaus." \
      org.opencontainers.image.source="https://github.com/GAS85/ssh-auth-logger" \
      org.opencontainers.image.url="https://hub.docker.com/r/GAS85/ssh-auth-logger" \
      org.opencontainers.image.documentation="https://github.com/GAS85/ssh-auth-logger#" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION

ENV VERSION=$VERSION
ENV COMMIT=$VCS_REF
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
    chmod 640 /var/log/ssh-auth-logger.log

USER $USER

EXPOSE 2222 2323

HEALTHCHECK \
    --interval=5m \
    --timeout=5s \
    --retries=1 \
    --start-period=5s \
    CMD ["sh", "-c", "pgrep ssh-auth-logger"]

CMD ["/bin/sh", "-c", "/go/bin/ssh-auth-logger"]
