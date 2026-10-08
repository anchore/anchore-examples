# ---------------------------------------------------------------------------
# Part of the Anchore Examples Repository.
# Licensed under the Apache License, Version 2.0 (the "License").
#
# THIS FILE IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
# ---------------------------------------------------------------------------

import json
import argparse
import hashlib
import sys
import datetime
import os

# Anchore severity -> GitLab severity. GitLab's enum is
# Info/Unknown/Low/Medium/High/Critical. (F7)
GITLAB_SEV = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "negligible": "Info",
    "unknown": "Unknown",
}

# Rank for the F8 merge: when two records normalize to the same identity, the union
# must keep the worse severity rather than whichever record happened to arrive first.
SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "Unknown": 0}

# Stamped into the report AND used by --validate/--help. One constant, so bumping the
# embedded schema cannot leave the report claiming a version GitLab then parses with
# the wrong parser.
SCHEMA_KIND = "container-scanning"
GITLAB_SCHEMA_VERSION = "15.2.4"


def die(msg):
    # F13: fail loudly with a non-zero exit instead of emitting a silently-wrong report.
    sys.stderr.write("ERROR: {}\n".format(msg))
    sys.exit(2)


def clean(v):
    # F13: Anchore stringifies absent values as the literal "None" (not null).
    if v is None:
        return None
    if isinstance(v, str) and v.strip() in ("", "None"):
        return None
    return v


def _snake(camel):
    return "".join("_" + c.lower() if c.isupper() else c for c in camel)


def pick(rec, camel):
    # F12: `-o json` is camelCase, `-o json-raw` is snake_case. Read either.
    if not isinstance(rec, dict):
        return None
    v = rec.get(camel)
    if v is None:
        v = rec.get(_snake(camel))
    return clean(v)


def ident_type(vid):
    # F3: derive identifier type from the value's prefix.
    u = (vid or "").upper()
    for pfx, t in (
        ("CVE-", "cve"), ("GHSA", "ghsa"), ("ELSA-", "elsa"), ("RHSA-", "rhsa"),
        ("RHBA-", "rhba"), ("USN-", "usn"), ("ALAS", "alas"), ("DSA-", "dsa"),
        ("DLA-", "dla"), ("GO-", "go"), ("VULNDB-", "vulndb"),
    ):
        if u.startswith(pfx):
            return t
    return "other"


def ident_url(name, itype):
    # F2: a URL is derivable from a CVE or GHSA id alone.
    if itype == "cve":
        return "https://nvd.nist.gov/vuln/detail/{}".format(name)
    if itype == "ghsa":
        return "https://github.com/advisories/{}".format(name)
    return None


def build_allowlist_and_recs(policy_data):
    # F4/F5/F11: build and RETURN the lookups (no module globals). Only the
    # vulnerabilities gate; split on the first "+"; require both parts; key the
    # allowlist on the (vuln, package) PAIR.
    allow = set()
    recs = {}
    # F12: every key here goes through pick(). Read raw, a snake_case (`-o json-raw`)
    # eval-data silently yielded an empty allowlist -- allowlisted/accepted-risk
    # findings re-published to GitLab -- and dropped every policy recommendation from
    # `solution`, while the run still reported "schema OK".
    for policy_eval in (pick(policy_data, "evaluations") or []):
        details = pick(policy_eval, "details") or {}
        for finding in (pick(details, "findings") or []):
            if pick(finding, "gate") != "vulnerabilities":
                continue
            tid = pick(finding, "triggerId") or ""
            if "+" not in tid:
                continue
            vuln_id, package = tid.split("+", 1)
            if not vuln_id or not package:
                continue
            if pick(finding, "allowlisted"):
                allow.add((vuln_id, package))
            rec = pick(finding, "recommendation")
            if rec:
                recs[(vuln_id, package)] = rec
    return allow, recs


def operating_system(image_data, on_missing="fail", default_os="unknown"):
    # F1: the OS is a property of the image, not the finding. Use
    # <distro>:<major.minor> so a base-image patch bump doesn't re-file every finding.
    # F12: pick(), not raw camelCase -- a snake_case image-data otherwise died with
    # "no imageContent.metadata.distro" on an image that plainly has a distro.
    meta = pick(image_data, "imageContent") or {}
    meta = pick(meta, "metadata") or {}
    distro = pick(meta, "distro")
    ver = pick(meta, "distroVersion")
    if not distro:
        # No OS distro (distroless/scratch, or a language-only image). Selectable so a
        # fail-loud default doesn't block OS-less images.
        if on_missing == "default":
            sys.stderr.write(
                "WARNING: image-data has no imageContent.metadata.distro; using "
                "operating_system='{}' (--on-missing-distro default) (F1)\n".format(default_os))
            return default_os
        die("image-data has no imageContent.metadata.distro; cannot set operating_system (F1). "
            "Pass --on-missing-distro default to fall back to --default-os instead.")
    if ver:
        return "{}:{}".format(distro, ".".join(str(ver).split(".")[:2]))
    return distro


def image_ref(policy_data, image_data):
    tag = pick(policy_data, "evaluatedTag")      # F12
    if tag:
        return tag
    detail = pick(image_data, "imageDetail") or []
    if detail:
        return pick(detail[0], "fullTag") or ""
    return ""


def stable_vuln_key(vuln, vid):
    # F15: feeds re-attribute an advisory between systems (nvd -> github:python was
    # observed on the same image across consecutive daily runs), which moves the
    # primary id and re-files the finding in GitLab. A CVE alias survives that where
    # the primary id does not, so prefer it for the location fingerprint only.
    # Display is unaffected -- this feeds the id hash only.
    # Sorted: nvdData's order is not guaranteed by the API, so an advisory aliasing
    # several CVEs could return a different "first" CVE between two daily runs,
    # flipping the hash and re-filing the finding -- the churn F15 exists to prevent.
    cves = sorted(str(c).upper() for c in
                  (clean(nd.get("id")) for nd in (pick(vuln, "nvdData") or []))
                  if c and str(c).upper().startswith("CVE-"))
    return cves[0] if cves else vid


def _norm_ts(t):
    # F17: GitLab requires exactly yyyy-mm-ddThh:mm:ss in UTC. Accept the forms
    # anchorectl may emit -- trailing Z, a numeric offset, fractional seconds, a
    # space separator -- and convert to UTC rather than truncating, which would
    # relabel an offset time as UTC.
    if not t:
        return None
    s = str(t).strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def scan_window(image_data):
    # F6/F17: guard timestamp extraction and normalize to UTC; fall back to a
    # wall-clock UTC window rather than aborting.
    dets = pick(image_data, "analysisStatusDetail") or []        # F12
    ts = sorted(x for x in (_norm_ts(pick(d, "timestamp"))
                            for d in dets if isinstance(d, dict)) if x)
    if ts:
        return ts[0], ts[-1]
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return now, now


def convert_to_container_scan(policy_data, vuln_data, image_data, allow, recs,
                              on_missing="fail", default_os="unknown"):
    os_value = operating_system(image_data, on_missing, default_os)   # F1: one value for the image
    image = image_ref(policy_data, image_data)
    if not image:
        die("could not determine image tag (evaluatedTag / imageDetail[0].fullTag) (F13)")

    # Full scanner/analyzer for the required top-level `scan` block. The GitLab
    # container-scanning schema requires scan{analyzer,scanner,start_time,end_time,
    # status,type} and scanner/analyzer{id,name,version,vendor.name} — without it the
    # whole report is rejected at ingestion (invisible on GitLab Free).
    scanner = {
        "id": "anchore-enterprise",
        "name": "Anchore Enterprise",
        "version": "enterprise",
        "vendor": {"name": "Anchore Inc."},
    }
    start_time, end_time = scan_window(image_data)
    scan = {
        "analyzer": dict(scanner),
        "scanner": dict(scanner),
        "start_time": start_time,
        "end_time": end_time,
        "status": "success",
        "type": "container_scanning",
    }

    vulnerabilities = []
    by_id = {}
    has_fix = {}
    omitted = 0
    merged = 0

    for vuln in vuln_data:
        vid = pick(vuln, "vuln")
        if not vid:
            die("a vuln record has no 'vuln' id (F13)")
        pkg = pick(vuln, "package")
        if not pkg:
            die("vuln {} has no package (F16)".format(vid))
        pkgname = pick(vuln, "packageName")
        if not pkgname:
            die("vuln {} has no packageName (F13)".format(vid))
        pkgvers = pick(vuln, "packageVersion")
        if not pkgvers:
            # GitLab's schema requires location.dependency.version to be a string.
            # A null there makes GitLab discard the WHOLE report at ingestion -- every
            # finding disappears silently -- so fail here instead (F13).
            die("vuln {} in {} has no packageVersion (F13)".format(vid, pkgname))
        pkgpath = pick(vuln, "packagePath") or "NA"

        # F5: allowlist is keyed on (vuln, package); the triggerId's package part is
        # sometimes the full package, sometimes the name, so match either.
        if (vid, pkg) in allow or (vid, pkgname) in allow:
            omitted += 1
            continue

        sev = pick(vuln, "severity") or "unknown"
        gvsev = GITLAB_SEV.get(sev.lower(), "Unknown")   # F7: default Unknown, not Info

        # Identifiers (F2 always present; F3 typed; URLs derived when possible).
        identifiers = []
        seen_ids = set()

        def add_ident(name, itype):
            if not name or (itype, name) in seen_ids:
                return
            seen_ids.add((itype, name))
            ent = {"type": itype, "name": name, "value": name}
            url = clean(vuln.get("url")) if name == vid else None
            url = url or ident_url(name, itype)
            if url:
                ent["url"] = url
            identifiers.append(ent)

        add_ident(vid, ident_type(vid))
        for nd in (pick(vuln, "nvdData") or []):
            cid = clean(nd.get("id"))
            if cid and str(cid).upper().startswith("CVE-"):
                add_ident(cid, "cve")

        # Links: advisory URL + NVD links for related CVEs.
        links = []
        seen_links = set()
        candidate = [clean(vuln.get("url"))]
        for nd in (pick(vuln, "nvdData") or []):
            cid = clean(nd.get("id"))
            if cid and str(cid).upper().startswith("CVE-"):
                candidate.append(ident_url(cid, "cve"))
        for lu in candidate:
            if lu and lu not in seen_links:
                seen_links.add(lu)
                links.append({"url": lu})

        # Solution from fix data + policy recommendation append.
        fixver = pick(vuln, "fix") or pick(vuln, "suggestedFixVersion")
        if fixver:
            solution = "Upgrade {} to {} (or later) to remediate {}.".format(pkgname, fixver, vid)
        elif pick(vuln, "willNotFix"):
            solution = "No fix available: the vendor has marked {} as will-not-fix for {}.".format(vid, pkgname)
        else:
            solution = "No fix currently available for {} in {}.".format(vid, pkgname)
        rec = recs.get((vid, pkg)) or recs.get((vid, pkgname))
        if rec:
            solution = "{} {}".format(solution, rec)

        # Description carries the triage context GitLab has no field for: the feed
        # group (F1 moved it out of operating_system), fix disposition and provenance.
        extras = []
        feed = pick(vuln, "feedGroup")
        if feed:
            extras.append("feed {}".format(feed))
        if pick(vuln, "willNotFix"):
            extras.append("vendor will-not-fix")
        if vuln.get("inheritedFromBase") is not None:
            extras.append("inheritedFromBase={}".format(bool(vuln.get("inheritedFromBase"))))
        description = "There is a vulnerability {} detected in installed package {} ({}).".format(
            vid, pkgname, pkgvers or "unknown version"
        )
        if extras:
            description = "{} [{}]".format(description, "; ".join(extras))

        # F15: key the fingerprint on the stable CVE alias, not the primary id.
        vhash = hashlib.sha256(
            "{}-{}-{}".format(stable_vuln_key(vuln, vid), pkg, pkgpath).encode("utf-8")
        ).hexdigest()

        prior = by_id.get(vhash)
        if prior is not None:
            # F8: two records normalized to the same identity (a flaw known to both
            # NVD and GHSA). Union identifiers/links into the existing finding rather
            # than emitting a colliding id that GitLab would resolve arbitrarily.
            merged += 1
            have = set((e["type"], e["value"]) for e in prior["identifiers"])
            for ent in identifiers:
                if (ent["type"], ent["value"]) not in have:
                    have.add((ent["type"], ent["value"]))
                    prior["identifiers"].append(ent)
            have_urls = set(lnk["url"] for lnk in prior["links"])
            for lnk in links:
                if lnk["url"] not in have_urls:
                    have_urls.add(lnk["url"])
                    prior["links"].append(lnk)
            # Union identifiers/links only, and the loser's triage data was lost:
            # iteration order over vuln_data is arbitrary, so the same CVE arriving
            # from the distro feed (Medium, no fix) before the NVD/GHSA feed (High,
            # with a fix version) reported Medium / "no fix available" and dropped the
            # actual remediation version. Keep the worse severity and the real fix.
            if SEV_RANK.get(gvsev, 0) > SEV_RANK.get(prior["severity"], 0):
                prior["severity"] = gvsev
            if fixver and not has_fix.get(vhash):
                prior["solution"] = solution
                prior["description"] = description
                has_fix[vhash] = True
            continue

        record = {
            "id": vhash,
            "category": "container_scanning",
            # F16: name excludes finding-specific info (the version); it lives in
            # location.dependency.version. message/description keep it (prose).
            "name": "{} in {}".format(vid, pkgname),
            "message": "{} in {}".format(vid, pkg),
            "description": description,
            "severity": gvsev,
            "solution": solution,
            "location": {
                "dependency": {"package": {"name": pkgname}, "version": pkgvers},
                "operating_system": os_value,           # F1
                "image": image,
            },
            "identifiers": identifiers,
            "links": links,
            "scanner": {"id": scanner["id"], "name": scanner["name"]},
        }
        vulnerabilities.append(record)
        by_id[vhash] = record
        has_fix[vhash] = bool(fixver)

    # F5/F8: make suppression and merges visible rather than silent.
    sys.stderr.write("container-scan: {} finding(s) omitted by allowlist\n".format(omitted))
    sys.stderr.write("container-scan: {} finding(s) merged into an existing identity (F8)\n".format(merged))
    return {"version": GITLAB_SCHEMA_VERSION, "vulnerabilities": vulnerabilities, "scan": scan}




def default_schema_path():
    # The GitLab schema ships as a sibling file rather than a base64 blob inside this
    # script, so it can be read, diffed and swapped. Resolved relative to the script
    # rather than the cwd, so it is found however the script is invoked -- including
    # the CI template, which writes both into the same directory.
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "gitlab-{}-schema-{}.json".format(SCHEMA_KIND, GITLAB_SCHEMA_VERSION))


def schema_url():
    # The schema is GitLab's, not ours, so it is not redistributed here -- it is
    # pinned to the tag GitLab publishes and fetched. Pinning (never `master`) means
    # the file you validate against is the one this version of the script was written
    # for, and a schema change upstream cannot silently alter what passes.
    return ("https://gitlab.com/gitlab-org/security-products/security-report-schemas"
            "/-/raw/v{v}/dist/{k}-report-format.json".format(
                v=GITLAB_SCHEMA_VERSION, k=SCHEMA_KIND))


def validate_report(report_path, schema_path=None):
    # Invoked by --validate or --schema. Errors (does not silently skip) if jsonschema is absent.
    try:
        import jsonschema
    except ImportError:
        die("schema validation requires the 'jsonschema' package (pip install -r requirements.txt)")
    if schema_path:
        # Caller-supplied schema (e.g. their GitLab version, or a vendored copy).
        try:
            with open(schema_path) as f:
                schema = json.load(f)
        except (OSError, ValueError) as e:
            die("could not read --schema %s: %s" % (schema_path, e))
        label = schema_path
    else:
        bundled = default_schema_path()
        try:
            with open(bundled) as f:
                schema = json.load(f)
        except (OSError, ValueError) as e:
            die("could not read the GitLab schema %s: %s\n"
                "       GitLab's schemas are not redistributed here. Fetch the pinned "
                "version with:\n         curl -sLo %s \\\n           %s\n"
                "       or pass --schema PATH to validate against your own copy."
                % (bundled, e, bundled, schema_url()))
        label = "GitLab schema %s" % GITLAB_SCHEMA_VERSION
    report = json.load(open(report_path))
    errs = sorted(jsonschema.Draft7Validator(schema).iter_errors(report), key=lambda e: list(e.absolute_path))
    if errs:
        sys.stderr.write("SCHEMA VALIDATION FAILED: %s vs %s (%d error(s)):\n" % (report_path, label, len(errs)))
        for e in errs[:20]:
            sys.stderr.write("  - [%s] %s\n" % ("/".join(map(str, e.absolute_path)) or "<root>", e.message[:160]))
        sys.exit(1)
    print("schema OK: %s conforms to %s" % (report_path, label))


def main():
    parser = argparse.ArgumentParser(
        description="Convert Anchore (anchorectl) image-scan output into a GitLab "
                    "Container Scanning report (schema version {}).".format(GITLAB_SCHEMA_VERSION),
        epilog=(
            "schema validation (--validate):\n"
            "  The official GitLab container-scanning schema (version {ver}) is embedded in this\n"
            "  script, so validation needs no network and works airgapped. --validate checks the\n"
            "  written report against it and exits non-zero on any violation. It requires the\n"
            "  'jsonschema' package (see requirements.txt) and ERRORS if that is not installed\n"
            "  (it never silently skips). Without --validate no validation runs and 'jsonschema'\n"
            "  is not needed.\n\n"
            "inputs (from `anchorectl ... -o json`; camelCase or snake_case both accepted):\n"
            "  --vuln-data   `anchorectl image vulnerabilities`  (the finding set)\n"
            "  --eval-data   `anchorectl image check --detail`   (allowlist + recommendations)\n"
            "  --image-data  `anchorectl image get`              (OS distro + tag; mandatory)\n"
        ).format(ver=GITLAB_SCHEMA_VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--vuln-data", required=True, help="anchorectl image vulnerabilities -o json")
    parser.add_argument("--eval-data", required=True, help="anchorectl image check --detail -o json")
    parser.add_argument("--image-data", required=True, help="anchorectl image get -o json (OS distro + tag)")
    parser.add_argument("--output", required=True, help="path to write the GitLab report JSON")
    parser.add_argument("--on-missing-distro", choices=("fail", "default"), default="fail",
                        help="image has no OS distro (distroless/scratch): 'fail' (default) or use --default-os")
    parser.add_argument("--default-os", default="unknown",
                        help="operating_system when --on-missing-distro=default (default: unknown)")
    parser.add_argument("--validate", action="store_true",
                        help="validate the output against the pinned GitLab schema (v{}); exit "
                             "non-zero on any violation; requires 'jsonschema' (errors if absent)".format(GITLAB_SCHEMA_VERSION))
    parser.add_argument("--schema", metavar="PATH",
                        help="validate against this GitLab schema JSON file instead of the embedded "
                             "one (implies --validate; use your instance's schema version if it differs)")
    args = parser.parse_args()

    def load(path, what):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (OSError, ValueError) as e:
            die("cannot read {} ({}): {}".format(what, path, e))

    eval_data = load(args.eval_data, "eval-data")
    vuln_data = load(args.vuln_data, "vuln-data")
    image_data = load(args.image_data, "image-data")

    # F12/F13: `-o json` puts the findings in a bare top-level array.
    if not isinstance(vuln_data, list):
        die("vuln-data is not a JSON array of findings (expected `anchorectl ... -o json`)")
    # F13: guard the other two the same way. They are read with .get(), so passing an
    # array-shaped JSON (an easy mix-up when all three flags take `anchorectl ... -o
    # json`) raised AttributeError with a traceback instead of a diagnostic.
    if not isinstance(eval_data, dict):
        die("eval-data is not a JSON object (expected `anchorectl image check --detail -o json`)")
    if not isinstance(image_data, dict):
        die("image-data is not a JSON object (expected `anchorectl image get -o json`)")

    allow, recs = build_allowlist_and_recs(eval_data)
    report = convert_to_container_scan(eval_data, vuln_data, image_data, allow, recs,
                                       args.on_missing_distro, args.default_os)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if args.validate or args.schema:
        validate_report(args.output, args.schema)


if __name__ == "__main__":
    main()
