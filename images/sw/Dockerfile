# Switch L2 : bridge Linux avec filtrage VLAN (802.1Q)
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping tcpdump procps \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
