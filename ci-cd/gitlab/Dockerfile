# ---------------------------------------------------------------------------
# Part of the Anchore Examples Repository.
# Licensed under the Apache License, Version 2.0 (the "License").
#
# THIS SCRIPT IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
# ---------------------------------------------------------------------------

# ubuntu:20.04 is intentionally used — it carries a number of unpatched OS-level
# CVEs that make it useful for demonstrating Anchore vulnerability reporting.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Pillow 9.3.0 has several known CVEs (e.g. CVE-2023-44271, CVE-2023-50447)
# and is pinned here intentionally to demonstrate Anchore's package-level
# vulnerability detection.
RUN pip3 install Pillow==9.3.0

WORKDIR /app

COPY . .

EXPOSE 8080
CMD ["python3", "-m", "http.server", "8080"]
