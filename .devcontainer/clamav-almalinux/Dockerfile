# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

FROM index.docker.io/library/almalinux:9.5 AS clamav-almalinux-devcontainer

# Declare the container args
ARG REMOTE_USER
ARG REMOTE_UID

# Set working directory
WORKDIR /src

# Copy current directory contents into the container
COPY . /src/

# Set environment variables
ENV CARGO_HOME=/src/build
ENV HOME=/home/${REMOTE_USER}

# Install and enable EPEL and CRB repositories
RUN dnf -y install epel-release && dnf config-manager --set-enabled crb

# Install necessary packages
RUN dnf -y --allowerasing install \
    cmake \
    bison \
    check \
    curl \
    flex \
    gcc \
    gcc-c++ \
    git \
    gdb \
    glibc-all-langpacks \
    make \
    man-db \
    net-tools \
    psmisc \
    pkg-config \
    python3-pip \
    python3-pytest \
    sudo \
    tcpdump \
    valgrind \
    wget \
    zip \
    bzip2-devel \
    check-devel \
    curl-devel \
    json-c-devel \
    sendmail-devel \
    ncurses-devel \
    pcre2-devel \
    openssl-devel \
    libxml2-devel \
    zlib-devel \
    && rm -rf /var/cache/apt/archives

RUN echo "REMOTE_USER is ${REMOTE_USER} and REMOTE_UID is ${REMOTE_UID}"

# Create a non-root user
RUN echo "Creating user ${REMOTE_USER} with UID ${REMOTE_UID}" && \
    adduser --uid "$REMOTE_UID" "$REMOTE_USER" && \
    echo "${REMOTE_USER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${REMOTE_USER} && chmod 0440 /etc/sudoers.d/${REMOTE_USER}

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && . $CARGO_HOME/env \
    && rustup update

# Switch to the non-root user
USER ${REMOTE_USER}

# Set working directory to user's home
WORKDIR ${HOME}