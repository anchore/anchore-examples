#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Part of the Anchore Examples Repository.
# Licensed under the Apache License, Version 2.0 (the "License").
#
# THIS FILE IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
# ---------------------------------------------------------------------------
"""
vulndata_apps.py — full NVD vulnerability descriptions for an Anchore
Enterprise 6.x Application Version.

Enterprise 6's /apps/{app_id}/versions/{version_id}/vulnerabilities endpoint
only returns match metadata (severity, CVSS, EPSS, KEV, anchore_score) - no
description text. This script chains three calls to get from an app/version
name to full descriptions:

  1. GET /apps?name=<APP>                                    -> app_id
  2. GET /apps/{app_id}/versions?name=<VERSION>               -> version_id
  3. GET /apps/{app_id}/versions/{version_id}/vulnerabilities -> vulnerability IDs
  4. GET /query/vulnerabilities?id=<CVE1,CVE2,...>            -> nvd_data[].description

Prerequisites: python3 (3.8+, stdlib only - nothing to pip install).

Usage:
    vulndata_apps.py APP_NAME VERSION_NAME
    vulndata_apps.py rust 2.0
    vulndata_apps.py rust 2.0 --output vulndata-rust.txt
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BATCH_SIZE = 50

# Same search order anchorectl itself uses for its config file.
ANCHORECTL_CONFIG_PATHS = [
    "./.anchorectl.yaml",
    "./anchorectl.yaml",
    "./.anchorectl/config.yaml",
    os.path.expanduser("~/.anchorectl.yaml"),
    os.path.expanduser("~/anchorectl.yaml"),
    os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
        "anchorectl",
        "config.yaml",
    ),
]


def load_anchorectl_config():
    """Pull url/username/password out of an anchorectl config file.

    Only reads top-level (unindented) `key: value` lines - good enough for
    the flat keys we need without pulling in a YAML dependency.
    """
    for path in ANCHORECTL_CONFIG_PATHS:
        if not os.path.isfile(path):
            continue
        values = {}
        with open(path) as f:
            for line in f:
                if not line.strip() or line[0] in " \t#" or ":" not in line:
                    continue
                key, _, value = line.partition(":")
                values[key.strip()] = value.split("#")[0].strip().strip("'\"")
        return values
    return {}


def resolve_config():
    config = load_anchorectl_config()
    username = os.environ.get("ANCHORECTL_USERNAME") or config.get("username")
    password = os.environ.get("ANCHORECTL_PASSWORD") or config.get("password")
    base_url = os.environ.get("ANCHORECTL_URL") or config.get("url")

    if not all([username, password, base_url]):
        sys.exit(
            "Error: missing credentials. Set ANCHORECTL_USERNAME, ANCHORECTL_PASSWORD, "
            "and ANCHORECTL_URL in your environment, or configure them in ~/.anchorectl.yaml."
        )

    base_url = base_url.rstrip("/")
    if not base_url.endswith("/v2"):
        base_url += "/v2"
    return base_url, username, password


def api_get(base_url, username, password, path, params=None):
    url = f"{base_url}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "Authorization": f"Basic {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"Error: {e.code} {e.reason} for {url}\n{e.read().decode(errors='replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"Error: could not reach {url}: {e.reason}")


def get_app_id(base_url, username, password, app_name):
    data = api_get(base_url, username, password, "/apps", {"name": app_name})
    items = data.get("items", [])
    if not items:
        sys.exit(f"Error: no app named {app_name!r} found")
    return items[0]["system_metadata"]["id"]


def get_version_id(base_url, username, password, app_id, version_name):
    data = api_get(
        base_url, username, password, f"/apps/{app_id}/versions", {"name": version_name}
    )
    items = data.get("items", [])
    if not items:
        sys.exit(f"Error: no version named {version_name!r} found")
    return items[0]["system_metadata"]["id"]


def get_vulnerability_ids(base_url, username, password, app_id, version_id):
    ids = []
    seen = set()
    cursor = None
    while True:
        params = {"limit": 1000}
        if cursor:
            params["cursor"] = cursor
        data = api_get(
            base_url,
            username,
            password,
            f"/apps/{app_id}/versions/{version_id}/vulnerabilities",
            params,
        )
        for item in data.get("items", []):
            vid = item["vulnerability_id"]
            if vid not in seen:
                seen.add(vid)
                ids.append(vid)
        cursor = data.get("pagination", {}).get("next_cursor")
        if not cursor:
            break
    return ids


def get_descriptions(base_url, username, password, vuln_ids):
    descriptions = {}
    for i in range(0, len(vuln_ids), BATCH_SIZE):
        batch = vuln_ids[i : i + BATCH_SIZE]
        data = api_get(
            base_url, username, password, "/query/vulnerabilities", {"id": ",".join(batch)}
        )
        for record in data.get("vulnerabilities", []):
            vid = record.get("id")
            if not vid or vid in descriptions:
                continue
            nvd_desc = next(
                (n.get("description") for n in record.get("nvd_data") or [] if n.get("description")),
                None,
            )
            descriptions[vid] = nvd_desc or record.get("description") or ""
    return descriptions


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("app_name", help="Application name (exact match)")
    parser.add_argument("version_name", help="Application version name (exact match)")
    parser.add_argument("-o", "--output", default="vulndata", help="Output file (default: vulndata)")
    args = parser.parse_args()

    base_url, username, password = resolve_config()

    app_id = get_app_id(base_url, username, password, args.app_name)
    version_id = get_version_id(base_url, username, password, app_id, args.version_name)
    vuln_ids = get_vulnerability_ids(base_url, username, password, app_id, version_id)

    if not vuln_ids:
        print(f"No vulnerabilities found for {args.app_name} {args.version_name}.")
        return

    descriptions = get_descriptions(base_url, username, password, vuln_ids)

    header = "-" * 58
    lines = [header, f"Vulnerability Report for {args.app_name} {args.version_name}", header]
    for vid in vuln_ids:
        desc = descriptions.get(vid) or "(no description available)"
        lines.append(f"{vid}: {desc}\n")

    output = "\n".join(lines)
    print(output)
    with open(args.output, "w") as f:
        f.write(output + "\n")


if __name__ == "__main__":
    main()
