FROM scratch
COPY traceroute-exporter /
ENTRYPOINT ["/traceroute-exporter"]
