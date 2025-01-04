FROM golang

RUN apt update && apt update && apt install -y iproute2 iptables

