FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/traceroute-exporter /
ENTRYPOINT ["/traceroute-exporter"]
