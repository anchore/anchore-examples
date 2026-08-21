# GitLab CI/CD — Anchore Enterprise Integration

This example demonstrates integrating **Anchore Enterprise** container image scanning into a GitLab CI/CD pipeline. The pipeline builds and pushes an image to the GitLab Container Registry, then uses `anchorectl` to trigger centralized analysis, report vulnerabilities, and enforce policy compliance.

---

## Overview

### Stage 1 — Build & Push (`build`)

Uses Docker-in-Docker (`docker:dind`) to build the image from a `Dockerfile` at the root of the repository and push it to the GitLab Container Registry with two tags: the pipeline IID and `latest`.

### Stage 2 — Security Analysis (`anchore-scan`)

Runs only after `build` succeeds. It performs the following steps:

1. **Install `anchorectl`** — Downloads and installs `anchorectl` v5.27.1 from the Anchore release mirror. Configuration for `anchorectl` is stored as CI/CD variables. See Variables section.
   > This step is not needed if you are using an image that already has `anchorectl` installed and configured.
2. **Verify API Connectivity** — Runs `anchorectl system status` to confirm that `anchorectl` can reach and authenticate to the Anchore Enterprise API before proceeding. This also reports the status of all **Anchore Enterprise** systems.
3. **Sync Registry Credentials** — Registers the GitLab Container Registry with Anchore Enterprise (skipped if already present) so Anchore can pull the image for analysis.
4. **Scan & Report** — Submits the image for analysis (`anchorectl image add --wait`), prints the vulnerability report, and runs a policy check. The pipeline fails if the image does not pass the active policy (`--fail-based-on-results`).

---

## Variables

Declare these in your project's **Settings → CI/CD → Variables**. Values that contain credentials should be marked as **Masked** and **Protected**.

| Variable | Where to Set | Description |
|---|---|---|
| `IMAGE_NAME` | Pipeline file | Repository path for the image (e.g. `demo/my-app`). |
| `IMAGE_TAG` | Pipeline file | Automatically set to `$CI_PIPELINE_IID`. Update to match your tagging strategy. |
| `CI_REGISTRY` | GitLab built-in | Hostname of the GitLab Container Registry — provided automatically. |
| `CI_REGISTRY_USER` | GitLab built-in | Username for registry access — provided automatically. |
| `CI_REGISTRY_PASSWORD` | GitLab built-in | Token for registry access — provided automatically. Also passed to Anchore as `ANCHORECTL_REGISTRY_PASSWORD` so it can pull the image. |
| `ANCHORECTL_URL` | CI/CD Variables | Full URL to the Anchore Enterprise API (e.g. `http://anchore.example.com:8228`). |
| `ANCHORECTL_USERNAME` | CI/CD Variables | Username for Anchore Enterprise API authentication. |
| `ANCHORECTL_PASSWORD` | CI/CD Variables (Masked) | Password for Anchore Enterprise API authentication. (Will also take an API key, see [Configuring AnchoreCTL](https://docs.anchore.com/current/docs/configuration/anchorectl/)). |
