# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2020 Olliver Schinagl <oliver@schinagl.nl>
# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

# hadolint ignore=DL3007  latest is the latest stable for alpine
FROM index.docker.io/library/alpine:latest AS builder

LABEL maintainer="ClamAV bugs <clamav-bugs@external.cisco.com>"

EXPOSE 3310
EXPOSE 7357

HEALTHCHECK CMD "clamdcheck.sh"

WORKDIR /src

COPY . /src/

# hadolint ignore=DL3008  We want the latest stable versions
RUN apk add --no-cache \
        bsd-compat-headers \
        bzip2-dev \
        check-dev \
        cmake \
        curl-dev \
        file \
        fts-dev \
        g++ \
        git \
        json-c-dev \
        libmilter-dev \
        libtool \
        libxml2-dev \
        linux-headers \
        make \
        ncurses-dev \
        openssl-dev \
        pcre2-dev \
        py3-pytest \
        zlib-dev \
    && \
    mkdir -p "./build" && cd "./build" && \
    cmake .. \
          -DCMAKE_BUILD_TYPE="Release" \
          -DCMAKE_INSTALL_PREFIX="/usr" \
          -DCMAKE_INSTALL_LIBDIR="/usr/lib" \
          -DAPP_CONFIG_DIRECTORY="/etc/clamav" \
          -DDATABASE_DIRECTORY="/var/lib/clamav" \
          -DENABLE_CLAMONACC=OFF \
          -DENABLE_EXAMPLES=OFF \
          -DENABLE_JSON_SHARED=ON \
          -DENABLE_MAN_PAGES=OFF \
          -DENABLE_MILTER=ON \
          -DENABLE_STATIC_LIB=OFF && \
    make DESTDIR="/clamav" -j$(($(nproc) - 1)) install && \
    rm -r \
       "/clamav/usr/include" \
       "/clamav/usr/lib/pkgconfig/" \
    && \
    sed -e "s|^\(Example\)|\# \1|" \
        -e "s|.*\(PidFile\) .*|\1 /run/lock/clamd.pid|" \
        -e "s|.*\(LocalSocket\) .*|\1 /run/clamav/clamd.sock|" \
        -e "s|.*\(TCPSocket\) .*|\1 3310|" \
        -e "s|.*\(TCPAddr\) .*|\1 0.0.0.0|" \
        -e "s|.*\(User\) .*|\1 clamav|" \
        -e "s|^\#\(LogFile\) .*|\1 /var/log/clamav/clamd.log|" \
        -e "s|^\#\(LogTime\).*|\1 yes|" \
        "/clamav/etc/clamav/clamd.conf.sample" > "/clamav/etc/clamav/clamd.conf" && \
    sed -e "s|^\(Example\)|\# \1|" \
        -e "s|.*\(PidFile\) .*|\1 /run/lock/freshclam.pid|" \
        -e "s|.*\(DatabaseOwner\) .*|\1 clamav|" \
        -e "s|^\#\(UpdateLogFile\) .*|\1 /var/log/clamav/freshclam.log|" \
        -e "s|^\#\(NotifyClamd\).*|\1 /etc/clamav/clamd.conf|" \
        -e "s|^\#\(ScriptedUpdates\).*|\1 yes|" \
        "/clamav/etc/clamav/freshclam.conf.sample" > "/clamav/etc/clamav/freshclam.conf" && \
    sed -e "s|^\(Example\)|\# \1|" \
        -e "s|.*\(PidFile\) .*|\1 /run/lock/clamav-milter.pid|" \
        -e "s|.*\(MilterSocket\) .*|\1 inet:7357|" \
        -e "s|.*\(User\) .*|\1 clamav|" \
        -e "s|^\#\(LogFile\) .*|\1 /var/log/clamav/milter.log|" \
        -e "s|^\#\(LogTime\).*|\1 yes|" \
        -e "s|.*\(\ClamdSocket\) .*|\1 unix:/run/clamav/clamd.sock|" \
        "/clamav/etc/clamav/clamav-milter.conf.sample" > "/clamav/etc/clamav/clamav-milter.conf" || \
    exit 1 && \
    ctest -V

FROM index.docker.io/library/alpine:latest

RUN apk add --no-cache \
        fts \
        json-c \
        libbz2 \
        libcurl \
        libltdl \
        libmilter \
        libstdc++ \
        libxml2 \
        ncurses-libs \
        pcre2 \
        tini \
        zlib \
    && \
    addgroup -S "clamav" && \
    adduser -D -G "clamav" -h "/var/lib/clamav" -s "/bin/false" -S "clamav" && \
    install -d -m 755 -g "clamav" -o "clamav" "/var/log/clamav"

COPY --from=builder "/clamav" "/"
COPY "./dockerfiles/clamdcheck.sh" "/usr/local/bin/"
COPY "./dockerfiles/docker-entrypoint.sh" "/init"

ENTRYPOINT [ "/init" ]
