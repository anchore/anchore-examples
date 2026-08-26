# vulndata

Both scripts here do the same thing — pull the **full NVD description** for every CVE affecting a given Application Version. The standard Enterprise vulnerability report only returns match metadata (severity, CVSS, etc.) with little or no description text, so these dig out the fuller `nvd_data[].description` text that the UI and `anchorectl` don't normally surface.

Pick the one that matches your Enterprise version — the underlying API changed between 5.x and 6.x.

| Script | Enterprise version | API used |
|---|---|---|
| [`vulndata.sh`](#vulndatash-enterprise-5x) | 5.x | `/applications` (legacy Application Management) |
| [`vulndata_apps.py`](#vulndata_appspy-enterprise-6x) | 6.x | `/apps` |

---

## `vulndata.sh` (Enterprise 5.x)

> [!IMPORTANT]
> This targets **Anchore Enterprise 5.x** only. It calls the legacy `/applications` API for [Application Management](https://docs.anchore.com/current/docs/application_management/), which does not exist in the same form in Enterprise 6.x — use `vulndata_apps.py` instead.

### Prerequisites

- `curl` and `jq` installed
- An Anchore Enterprise 5.x deployment with API access
- The target Application and Application Version must already exist in Anchore (created via SBOM import) — this script only reads existing data, it does not create or scan anything

### Configuration

Credentials come from your environment first, then fall back to an `anchore.env` file — never hardcode them in the script.

If you already have `anchorectl` configured in your shell (`ANCHORECTL_USERNAME`, `ANCHORECTL_PASSWORD`, `ANCHORECTL_URL`), the script reuses those automatically — no extra setup needed. Otherwise, create an `anchore.env` file next to `vulndata.sh`:

```bash
# anchore.env
USERNAME=admin
PASSWORD=foobar
ANCHORE_URL=https://anchore.example.com/v2
```

> `ANCHORECTL_URL` typically points at the base API (e.g. `http://anchore.example.com:8228`) without a version suffix. This script hits the `/applications` endpoint directly, so make sure whichever URL is used (env var or `anchore.env`) includes the correct base path (often `/v2`) for your deployment.

Then edit the two variables near the top of `vulndata.sh` to point at the Application and Version you want a report for:

```bash
APP_NAME="rust"
TARGET_VERSION="2.0"
```

> In a GitLab CI job you can set `APP_NAME` from `$CI_PROJECT_NAME` and `TARGET_VERSION` from a git tag instead of hardcoding them.

### Usage

```bash
chmod +x vulndata.sh
./vulndata.sh
```

The script will:

1. Look up the `application_id` and `application_version_id` for `APP_NAME` / `TARGET_VERSION`.
2. Fetch the vulnerability report for that Application Version.
3. Print each CVE ID and its NVD description, and save the same output to a file named `vulndata` in the current directory (overwritten on each run).

### Notes

- Exits early with an error if the Application/Version name pair can't be found, or if credentials are missing.
- Only vulnerabilities with an `nvd` entry are included — findings without NVD data (e.g. GHSA-only advisories) won't appear in the output.

---

## `vulndata_apps.py` (Enterprise 6.x)

> [!IMPORTANT]
> This targets **Anchore Enterprise 6.x**, which replaced `/applications` with the `/apps` API. Use `vulndata.sh` for 5.x deployments.

Enterprise 6's `/apps/{app_id}/versions/{version_id}/vulnerabilities` endpoint only returns match metadata (severity, CVSS, EPSS, KEV, `anchore_score`) — no description text at all. Getting the description back requires an extra round trip to the standalone vulnerability catalog, which is more than is comfortable to chain together in `bash`/`jq`, so this one's Python.

### What it does

1. `GET /apps?name=<APP_NAME>` → resolves the app ID
2. `GET /apps/{app_id}/versions?name=<VERSION_NAME>` → resolves the version ID
3. `GET /apps/{app_id}/versions/{version_id}/vulnerabilities` → collects every matched CVE ID (paginated via cursor)
4. `GET /query/vulnerabilities?id=<CVE1,CVE2,...>` → looks up each CVE in batches of 50 and pulls `nvd_data[].description`

### Prerequisites

- `python3` (3.8+, standard library only — nothing to `pip install`)
- An Anchore Enterprise 6.x deployment with API access
- The target App and App Version must already exist in Anchore — this script only reads existing data

### Configuration

No `anchore.env` file here — being Python, it reads credentials the same way `anchorectl` itself does:

1. `ANCHORECTL_USERNAME` / `ANCHORECTL_PASSWORD` / `ANCHORECTL_URL` environment variables, if set
2. Otherwise, your `anchorectl` config file (`.anchorectl.yaml`, `~/.anchorectl.yaml`, `$XDG_CONFIG_HOME/anchorectl/config.yaml`, etc. — same search order anchorectl uses), reading its `url` / `username` / `password` keys

If you already use `anchorectl` against this deployment, there's nothing to configure.

It also normalizes the base URL itself — it appends `/v2` automatically if the URL doesn't already end in it, so a bare `ANCHORECTL_URL` (e.g. `http://anchore.example.com:8228`) or config `url:` works as-is.

### Usage

```bash
chmod +x vulndata_apps.py
./vulndata_apps.py <APP_NAME> <VERSION_NAME>

# example
./vulndata_apps.py rust 2.0

# custom output file (default: vulndata)
./vulndata_apps.py rust 2.0 --output vulndata-rust.txt
```

### Notes

- Exits early with an error if the app/version name pair can't be found, if credentials are missing, or on any non-2xx API response (the error includes the response body).
- If a CVE has multiple `nvd_data` entries, the first with a non-empty `description` is used; if there's no NVD data at all, it falls back to the record's generic `description`, or prints `(no description available)`.
- App and version names are matched exactly (case-sensitive), same as the API's `name` filter.
