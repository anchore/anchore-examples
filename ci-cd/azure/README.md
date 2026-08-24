# Azure DevOps Pipelines — Anchore Enterprise Integration

This example demonstrates integrating **Anchore Enterprise** container image scanning into an Azure DevOps pipeline. The pipeline builds and pushes an image to Azure Container Registry (ACR), then uses `anchorectl` to trigger centralized analysis, report vulnerabilities, and enforce policy compliance. 

---

## Overview

### Stage 1 — Build & Push (`BuildStage`)

Uses the Azure `Docker@2` task to build the image from a `Dockerfile` at the root of the repository and push it to ACR with two tags: the `Build.BuildId` and `latest`.

### Stage 2 — Security Analysis (`SecurityStage`)

Runs only after `BuildStage` succeeds. It performs the following steps:

1. **Install `anchorectl`** — Downloads and installs `anchorectl` v5.27.1 from the Anchore release mirror. Configurations for anchorectl are stored as environment variables. See Variables section.
	> This step is not needed if you are using an image that already has `anchorectl` installed and configured. Example references the provided `ubuntu-latest` VM image from Azure.
2. **Verify API Connectivity** — Runs `anchorectl system status` to confirm that `anchorectl` can reach and authenticate to the Anchore Enterprise API before proceeding. This also reports the status of all **Anchore Enterprise** systems.
3. **Sync Registry Credentials** — Registers the ACR with Anchore Enterprise (skipped if already present) so Anchore can pull the image for analysis.
4. **Scan & Report** — Submits the image for analysis (`anchorectl image add --wait`), prints the vulnerability report, and runs a policy check. The pipeline fails if the image does not pass the active policy (`--fail-based-on-results`).

---

## Variables

Declare these in your pipeline's **Variables** or **Variable Group**. Values that contain credentials should be marked as **secret**.

| Variable | Where to Set | Description |
|---|---|---|
| `dockerRegistryConnection` | Pipeline | Name of the Azure DevOps service connection for ACR — update to match your service connection. |
| `imageName` | Pipeline | Repository path for the image (e.g. `demo/my-app`). |
| `imageTag` | Pipeline |Automatically set to `$(Build.BuildId)` and does not need to be defined manually, but we recommend an appropriate tag for your own dev/test processes. |
| `ACR_REGISTRY` | Pipeline | Hostname of your ACR (e.g. `myregistry.azurecr.io`). |
| `ACR_USERNAME` | Pipeline | Username for ACR access (often the registry name for admin access). |
| `ACR_PASSWORD` | Pipeline (mark *secret*) | Password or token for ACR access. |
| `ANCHORECTL_URL` | Pipeline or library | Full URL to the Anchore Enterprise API (e.g. `http://anchore.example.com:8228`). |
| `ANCHORECTL_USERNAME` | Pipeline or library | Username for Anchore Enterprise API authentication. |
| `ANCHORECTL_PASSWORD` | Pipeline (mark *secret*) | Password for Anchore Enterprise API authentication. (Will also take an API key, see [Configuring AnchoreCTL](https://docs.anchore.com/current/docs/configuration/anchorectl/)). |

