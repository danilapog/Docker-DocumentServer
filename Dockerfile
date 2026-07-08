# syntax=docker/dockerfile:1
ARG BASE_VERSION=24.04
ARG BASE_IMAGE=ubuntu:${BASE_VERSION}
FROM $BASE_IMAGE
LABEL maintainer="Ascensio System SIA <support@onlyoffice.com>"

ENV LC_ALL=en_US.UTF-8 LANGUAGE=en_US:en DEBIAN_FRONTEND=noninteractive

# Install base OS dependencies: locale, cron, supervisor, network tools.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && \
    apt-get -y update && apt-get -yq install --no-install-recommends \
        $(: tools) ca-certificates curl gnupg locales sudo cron netcat-openbsd supervisor && \
    locale-gen ${LC_ALL} && rm -rf /var/lib/apt/lists/*

ARG COMPANY_NAME=onlyoffice
ARG PRODUCT_NAME=documentserver
ARG PRODUCT_EDITION=
ARG PACKAGE_VERSION=
ARG TARGETARCH
ARG PACKAGE_BASEURL="https://download.onlyoffice.com/install/documentserver/linux"
ENV COMPANY_NAME=$COMPANY_NAME PRODUCT_NAME=$PRODUCT_NAME PRODUCT_EDITION=$PRODUCT_EDITION \
    DS_PLUGIN_INSTALLATION=false DS_DOCKER_INSTALLATION=true

# Copy fonts, supervisor configs, and entrypoint scripts.
COPY fonts/ /usr/share/fonts/truetype/
COPY --exclude=ds-adminpanel.conf --exclude=ds.conf.enterprise config/supervisor/ /etc/supervisor/conf.d/
COPY run-document-server.sh /app/ds/run-document-server.sh

# Download and install the document server package, verify msttcorefonts.
RUN PACKAGE_FILE="${COMPANY_NAME}-${PRODUCT_NAME}${PRODUCT_EDITION}${PACKAGE_VERSION:+_$PACKAGE_VERSION}_${TARGETARCH:-$(dpkg --print-architecture)}.deb" && \
    curl -fsSLo /tmp/$PACKAGE_FILE "$PACKAGE_BASEURL/$PACKAGE_FILE" && \
    curl -fsSL https://download.onlyoffice.com/GPG-KEY-ONLYOFFICE | gpg --batch --yes --dearmor -o /usr/share/keyrings/onlyoffice.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/onlyoffice.gpg] https://download.onlyoffice.com/repo/debian squeeze main" > /etc/apt/sources.list.d/onlyoffice.list && \
    echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true | debconf-set-selections && \
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/nginx.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/nginx.gpg] https://nginx.org/packages/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) nginx" > /etc/apt/sources.list.d/nginx.list && \
    apt-get -y update && apt-get -yq install --no-install-recommends nginx /tmp/$PACKAGE_FILE && \
    rm -f /etc/nginx/conf.d/default.conf && \
    sed -i "s/COMPANY_NAME/${COMPANY_NAME}/g" /etc/supervisor/conf.d/*.conf && \
    [ "$(find /usr/share/fonts/truetype/msttcorefonts -maxdepth 1 -type f -iname '*.ttf' | wc -l)" -ge 30 ] || \
        { echo 'msttcorefonts failed to download'; exit 1; } && \
    rm -rf /tmp/$PACKAGE_FILE /var/log/$COMPANY_NAME /var/lib/apt/lists/*

EXPOSE 80 443
VOLUME /var/log/$COMPANY_NAME /var/lib/$COMPANY_NAME /var/www/$COMPANY_NAME/Data /usr/share/fonts/truetype/custom

# In data-container mode docservice never starts, so only check that nginx responds.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD if [ "$ONLYOFFICE_DATA_CONTAINER" != "true" ]; then [ "$(curl -fs http://127.0.0.1/healthcheck)" = "true" ]; else curl -fso /dev/null http://127.0.0.1/; fi

ENTRYPOINT ["/app/ds/run-document-server.sh"]
