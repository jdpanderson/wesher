FROM docker.io/golang:1.27

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update \
 && apt install -y git make gcc iputils-ping iproute2 wireguard-tools \
 && rm -rf /var/lib/apt/lists/*
RUN go install golang.zx2c4.com/wireguard@latest

COPY entrypoint.sh /

WORKDIR /app

ENTRYPOINT [ "/entrypoint.sh" ]