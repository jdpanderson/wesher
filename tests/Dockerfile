FROM docker.io/golang:1.27

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update \
 && apt install -y git make gcc iputils-ping iproute2 wireguard-tools \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /

WORKDIR /app

ENTRYPOINT [ "/entrypoint.sh" ]