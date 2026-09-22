# strongSwan gateway + traffic tools + capture/parse tools, all in one image.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
      strongswan strongswan-starter \
      iperf3 tcpdump tshark iproute2 iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*
# allow IPsec + forwarding
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
