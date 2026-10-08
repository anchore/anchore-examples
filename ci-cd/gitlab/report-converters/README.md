# Anchore → GitLab security report converters

Convert `anchorectl` image-scan output into native GitLab security reports, so
Anchore findings appear in GitLab's Vulnerability Report and merge-request
security widget rather than only in job logs.

| Converter | Produces | `artifacts:reports:` key |
|---|---|---|
| [`container-scanning/convert.py`](container-scanning/convert.py) | `gl-container-scan.json` | `container_scanning` |
| [`sast/transform.py`](sast/transform.py) | `gl-sast-report.json` | `sast` |

Both take the same three inputs and need only Python 3.6+ (plus `jsonschema`, and
only if you use `--validate`).

## Usage

```bash
anchorectl image vulnerabilities --include-description -o json "$IMAGE" > vulns.json
anchorectl image check --detail -o json                        "$IMAGE" > policy_eval.json
anchorectl image get -o json                                   "$IMAGE" > image_data.json

python3 container-scanning/convert.py \
  --vuln-data vulns.json --eval-data policy_eval.json --image-data image_data.json \
  --output gl-container-scan.json
```

Both `-o json` (camelCase) and `-o json-raw` (snake_case) are accepted.

Then publish it from your `.gitlab-ci.yml`:

```yaml
artifacts:
  reports:
    container_scanning: gl-container-scan.json
```

> **Note**
> GitLab parses security reports on Ultimate. On other tiers the artifact
> uploads and is stored, but no Vulnerability Report is produced.

## Schema validation

`--validate` checks the output against GitLab's published schema and exits
non-zero on any violation. The schemas are **GitLab's**, not ours, so they are
not redistributed in this repo — fetch the pinned version next to the script:

```bash
curl -sLo container-scanning/gitlab-container-scanning-schema-15.2.4.json \
  https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.2.4/dist/container-scanning-report-format.json

curl -sLo sast/gitlab-sast-schema-15.2.4.json \
  https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.2.4/dist/sast-report-format.json
```

Both converters are pinned to schema **15.2.4** and stamp that version into the
report. The pin is deliberate: the tag you validate against is the one these
scripts were written for, so an upstream schema change cannot silently alter
what passes. Run `--validate` without the file present and the error prints the
exact `curl` for the version in use. Use `--schema PATH` to check against your
own instance's copy instead.

Schema versions are numbered independently of the GitLab product — 15.2.x is the
current schema line, not a GitLab 15.x artifact.

## Fixtures

`container-scanning/sample-artifacts/` holds a real three-file capture from an
Ubuntu-based Python image, used by both converters and by CI. The registry
hostname is rewritten to `registry.example.com`.

## Options worth knowing

| Flag | Why |
|---|---|
| `--on-missing-distro default` | Distroless/scratch images have no OS distro; by default that is a hard error rather than a silently mislabelled report. |
| `--default-os` | The value used when the above is set. |
| `--schema PATH` | Validate against a schema file you supply. |

## License

```
# ---------------------------------------------------------------------------
# Part of the Anchore Examples Repository.
# Licensed under the Apache License, Version 2.0 (the "License").
#
# THIS FILE IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
# ---------------------------------------------------------------------------
```

That notice is carried at the top of every file in this directory that supports
comments. It applies equally to the JSON fixtures under
`container-scanning/sample-artifacts/`, which cannot carry it inline because
JSON has no comment syntax, and to this README.

GitLab's report schemas are **not** covered by it — they are not redistributed
here. They are fetched from GitLab at a pinned tag and remain under their own
upstream licence.
