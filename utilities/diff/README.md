# diff

`anchore-app-diff` is a visual CLI diff of two versions of an [application](https://docs.anchore.com/current/docs/application_management/) in Anchore Enterprise. It compares the packages (SBOM contents), vulnerabilities, and policy findings of the two versions and prints what was added, removed, changed, introduced, and resolved between them — with severity breakdowns, fix versions, Anchore risk scores, CISA KEV flags, and policy gate actions.

Useful for answering "what actually changed in our software composition between release 1.0.0 and 1.0.1?" — for release reviews, supplier SBOM comparisons, or as a CI gate (`--fail-on high --fail-on stop` exits 2 when the new version introduces vulns at/above a severity or new stop-action policy findings).

## Prerequisites

- `python3` (3.8+, standard library only — nothing to `pip install`)
- [`anchorectl`](https://docs.anchore.com/current/docs/deployment/anchorectl/) on your `PATH`, configured to reach your Anchore Enterprise deployment (`~/.anchorectl.yaml` or `ANCHORECTL_URL` / `ANCHORECTL_USERNAME` / `ANCHORECTL_PASSWORD`) — the script fetches all data through anchorectl with read-only `list`/`get` calls
- Both app versions must already exist in your deployment (e.g. via SBOM import or image analysis). Find them with `anchorectl app list` and `anchorectl app version list <APP>`.

## Usage

```bash
chmod +x anchore-app-diff

# full diff: packages + vulnerabilities + policy findings
./anchore-app-diff --app myapp 1.0.0 1.0.1

# a single section
./anchore-app-diff --app myapp 1.0.0 1.0.1 --section vulns   # or packages, policy

# CI gate
./anchore-app-diff --app myapp 1.0.0 1.0.1 --fail-on high --fail-on stop
```

Run `./anchore-app-diff --help` for all options and exit codes.
