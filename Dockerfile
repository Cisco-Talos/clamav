# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2020 Olliver Schinagl <oliver@schinagl.nl>
# Copyright (C) 2021-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

FROM index.docker.io/library/rust:1.62.1-bullseye AS builder

WORKDIR /src

COPY . /src/

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y \
        cmake \
        bison \
        flex \
        gcc \
        git \
        make \
        man-db \
        net-tools \
        pkg-config \
        python3 \
        python3-pip \
        python3-pytest \
        check \
        libbz2-dev \
        libcurl4-openssl-dev \
        libjson-c-dev \
        libmilter-dev \
        libncurses5-dev \
        libpcre2-dev \
        libssl-dev \
        libxml2-dev \
        zlib1g-dev \
    && \
    rm -rf /var/cache/apt/archives \
    && \
    mkdir -p "./build" && cd "./build" \
    && \
    cmake .. \
          -DCARGO_HOME="/src/build" \
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
          -DENABLE_STATIC_LIB=OFF \
    && \
    make DESTDIR="/clamav" -j$(($(nproc) - 1)) install \
    && \
    rm -r \
       "/clamav/usr/include" \
       "/clamav/usr/lib/pkgconfig/" \
    && \
    sed -e "s|^\(Example\)|\# \1|" \
        -e "s|.*\(PidFile\) .*|\1 /run/lock/clamd.pid|" \
        -e "s|.*\(LocalSocket\) .*|\1 /run/clamav/clamd.sock|" \
        -e "s|.*\(TCPSocket\) .*|\1 3310|" \
        -e "s|.*\(TCPAddr\) .*|#\1 0.0.0.0|" \
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
    exit 1 \
    && \
    ctest -V

FROM index.docker.io/library/debian:11-slim

LABEL maintainer="ClamAV bugs <clamav-bugs@external.cisco.com>"

EXPOSE 3310
EXPOSE 7357

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ Etc/UTC

RUN apt-get update && apt-get install -y \
        libbz2-1.0 \
        libcurl4 \
        libssl1.1 \
        libjson-c5 \
        libmilter1.0.1 \
        libncurses5 \
        libpcre2-8-0 \
        libxml2 \
        zlib1g \
        tzdata \
    && \
    rm -rf /var/cache/apt/archives && \
    groupadd "clamav" && \
    useradd -g clamav -s /bin/false --home-dir /var/lib/clamav -c "Clam Antivirus" clamav && \
    install -d -m 755 -g "clamav" -o "clamav" "/var/log/clamav"

COPY --from=builder "/clamav" "/"

COPY "./dockerfiles/clamdcheck.sh" "/usr/local/bin/"
COPY "./dockerfiles/docker-entrypoint.sh" "/init"

HEALTHCHECK --start-period=6m CMD "clamdcheck.sh"

ENTRYPOINT [ "/init" ]
