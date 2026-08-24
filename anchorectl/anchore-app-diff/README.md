# anchore-app-diff

A visual CLI diff of two versions of an [application](https://docs.anchore.com/current/docs/application_management/) in Anchore Enterprise. It compares the packages (SBOM contents), vulnerabilities, and policy findings of two app versions and prints what was **added, removed, changed, introduced, and resolved** between them — with severity breakdowns, fix versions, Anchore risk scores, CISA KEV flags, and policy gate actions.

Useful for answering "what actually changed in our software composition between release 1.0.0 and 1.0.1?" — for release reviews, supplier SBOM comparisons, or as a CI gate.

```
┌──────────────────────────────────────────────────────────────────┐
│               VULNERABILITY DIFF   jarjar 1.0.0 → 1.0.1          │
└──────────────────────────────────────────────────────────────────┘
  1.0.0      356 total   Critical: 43   High: 113   Medium: 180   Low: 20
  1.0.1      375 total   Critical: 44   High: 130   Medium: 181   Low: 20
  delta      ▲ +19   +19 introduced  -0 resolved

  ▲ INTRODUCED IN 1.0.1  (19)
    + CRITICAL CVE-2022-42889  commons-text@1.9       score 65.5  fix: 1.10.0
    + HIGH     CVE-2021-39144  xstream@1.4.17    KEV  score 94.1  fix: 1.4.18
    ...
```

## Prerequisites

- `python3` (3.8+, standard library only — nothing to `pip install`)
- [`anchorectl`](https://docs.anchore.com/current/docs/deployment/anchorectl/) on your `PATH`, configured to reach your Anchore Enterprise deployment (`~/.anchorectl.yaml` or `ANCHORECTL_URL` / `ANCHORECTL_USERNAME` / `ANCHORECTL_PASSWORD`)
- Both app versions must already exist in your deployment (e.g. via SBOM import or image analysis). Find them with `anchorectl app list` and `anchorectl app version list <APP>`.

## Usage

```bash
chmod +x anchore-app-diff

# full diff: packages + vulnerabilities + policy findings
./anchore-app-diff --app myapp 1.0.0 1.0.1

# a single section
./anchore-app-diff --app myapp 1.0.0 1.0.1 --section packages   # or vulns, policy

# CI gate: exit 2 if 1.0.1 introduces high/critical vulns or any
# new stop-action policy finding
./anchore-app-diff --app myapp 1.0.0 1.0.1 --fail-on high --fail-on stop

# keep colors when piping to a pager
./anchore-app-diff --app myapp 1.0.0 1.0.1 --color always | less -R
```

## Options

| Flag | Description |
|---|---|
| `--app APP` | App name or ID (required) |
| `--section {packages,vulns,policy,all}` | Which diff to show (default: `all`) |
| `--fail-on COND` | Exit 2 if the new version introduces a vuln at or above this severity (`critical`/`high`/`medium`/`low`) or a new `stop`-action policy finding (`stop`). Repeatable. |
| `--timeout SECONDS` | Timeout per anchorectl call (default: 120) |
| `--color {auto,always,never}` | Color output; `auto` disables color when piped (also respects `NO_COLOR`) |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (anchorectl missing, request failed, bad arguments) |
| 2 | A `--fail-on` condition matched |

## Notes

- All data is fetched live from your deployment; the script makes read-only `list`/`get` calls and changes nothing.
- Vulnerabilities are keyed by (CVE, package purl), so the same CVE moving to a new package version shows as resolved+introduced.
- The policy findings list can repeat identical rows per occurrence; the diff dedupes to one row per distinct (gate, rule, trigger) finding and shows both counts.

See the [repository README](../../README.md) for the license and support disclaimer that applies to everything in this repo.
