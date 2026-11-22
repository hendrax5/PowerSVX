# Load generator for the Reference Load benchmark.
# Build from the repository root:
#   docker build -f scripts/bench/Dockerfile -t powersvx-bench .
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends dnsperf openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY scripts/bench/gen-queryset.sh scripts/bench/parse-dnsperf.sh scripts/bench/run.sh /opt/bench/
COPY deploy/linux/dns-ready.sh /opt/bench/dns-ready.sh

WORKDIR /work
ENTRYPOINT ["bash"]
