# Dockerfile for MiniDNS
# Uses Debian slim as it provides glibc compatible with the compiled binary.
FROM debian:stable-slim

# Install any runtime dependencies (none required beyond libc)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary into the image
COPY minidns /usr/local/bin/minidns

# Create a directory for the hosts file that can be mounted
RUN mkdir -p /data && chmod 755 /data

# Environment variables for configuration (override in docker‑compose.yml)
ENV DOMAIN="local"
ENV PRIMARY_DNS="9.9.9.9"
ENV SECONDARY_DNS="1.1.1.1"

# Entry point runs the server using the provided environment variables.
# -f points to /data/hosts (to be mounted from the host).
# -l listens on all interfaces (0.0.0.0).
# Primary/secondary DNS are added only if the variables are non‑empty.
ENTRYPOINT ["/bin/sh","-c","exec /usr/local/bin/minidns \"$DOMAIN\" -f /data/hosts -l 0.0.0.0 ${PRIMARY_DNS:+-p $PRIMARY_DNS} ${SECONDARY_DNS:+-s $SECONDARY_DNS}"]
