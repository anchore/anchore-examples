FROM jenkins/jenkins:lts

# Switch to root to install system packages
USER root

# 1. Install Docker CLI and clean up apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl docker.io && \
    rm -rf /var/lib/apt/lists/*

# 2. Download, Extract, and Clean up in one step
# -sSfL: Silent, show errors, fail on server error, follow redirects
# tar -xz: extract (x) and uncompress (z)
# -C /usr/local/bin: change directory to the destination before extracting
RUN curl -sSfL https://anchorectl-releases.anchore.io/anchorectl/v5.26.0/anchorectl_5.26.0_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/anchorectl

# 3. Set Environment Variables
ENV ANCHORECTL_URL=http://api:8228
ENV ANCHORECTL_USERNAME=admin
ENV ANCHORECTL_PASSWORD=foobar
