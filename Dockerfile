FROM library/debian:trixie-slim
COPY traceroute-exporter /
RUN chmod +x /traceroute-exporter
ENTRYPOINT ["/traceroute-exporter"]
