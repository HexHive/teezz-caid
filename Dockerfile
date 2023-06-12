# syntax=docker/dockerfile:latest
ARG BUSYBOX_URL=https://github.com/meefik/busybox/releases/download/1.34.1/busybox-v1_34_1.zip
ARG BUSYBOX_SHA=5bef8fd3fa5cec7f244e78a6e245669777c47555c2d7406d8f6f275db826f151

FROM ubuntu:20.04 as teezz-caid
ARG BUSYBOX_URL
ARG BUSYBOX_SHA

# install prerequisites
ENV DEBIAN_FRONTEND=noninteractive

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && \
    apt install -y --no-install-recommends \
        build-essential \
        gcc \
        vim \
        wget \
        file \
        make \
        python3 \
        python3-pip \
        python-is-python3 \
        android-tools-adb \
        unzip \
        libz-dev \
        git \
        default-jre-headless \
        graphviz
        #&& rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install ipdb ipython

WORKDIR /opt
RUN wget https://github.com/skylot/jadx/releases/download/v1.3.0/jadx-1.3.0.zip \
      && unzip jadx-1.3.0.zip -d jadx \
      && git clone https://github.com/anestisb/vdexExtractor


ADD --link $BUSYBOX_URL /busybox.zip

RUN echo "$BUSYBOX_SHA  /busybox.zip" | sha256sum -c - && \
    unzip /busybox.zip -d /busybox

# build vdexExtractor
RUN cd /opt/vdexExtractor; ./make.sh
ENV PATH /opt/vdexExtractor/bin:/opt/jadx/bin:$PATH

# extend PYTHONPATH
ENV PYTHONPATH $PYTHONPATH:/opt/caid
