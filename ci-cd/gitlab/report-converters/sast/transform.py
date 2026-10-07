import json
import argparse
import hashlib
import sys
import datetime
import os

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
SCHEMA_KIND = "sast"
# 15.2.4, matching the container-scanning converter. The schema previously bundled
# here was labelled 15.0.6 but was byte-identical to upstream v15.2.4, so reports
# were stamped 15.0.6 while being validated against 15.2.4. The report content
# conforms to both; this makes the declared version match the one we check.
GITLAB_SCHEMA_VERSION = "15.2.4"

GITLAB_SAST_TEMPLATE = {
    "version": GITLAB_SCHEMA_VERSION,
    "vulnerabilities": [],
    "scan": {},
    "remediations": [],
}


def die(msg):
    sys.stderr.write("ERROR: {}\n".format(msg))
    sys.exit(2)


def clean(v):
    if v is None:
        return None
    if isinstance(v, str) and v.strip() in ("", "None"):
        return None
    return v


def _snake(camel):
    return "".join("_" + c.lower() if c.isupper() else c for c in camel)


def pick(rec, camel):
    if not isinstance(rec, dict):
        return None
    v = rec.get(camel)
    if v is None:
        v = rec.get(_snake(camel))
    return clean(v)


def ident_type(vid):
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
    if itype == "cve":
        return "https://nvd.nist.gov/vuln/detail/{}".format(name)
    if itype == "ghsa":
        return "https://github.com/advisories/{}".format(name)
    return None


def build_allowlist_and_recs(policy_data):
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
    # F1: image-derived, <distro>:<major.minor>.
    # F12: pick(), not raw camelCase -- a snake_case image-data otherwise died with
    # "no imageContent.metadata.distro" on an image that plainly has a distro.
    meta = pick(image_data, "imageContent") or {}
    meta = pick(meta, "metadata") or {}
    distro = pick(meta, "distro")
    ver = pick(meta, "distroVersion")
    if not distro:
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


def shared_package_paths(vuln_data):
    # GitLab's SAST parser keys each finding's location on location.file, so a path
    # shared by many packages collapses them all into one entry. Anchore reports the
    # package DATABASE as the path for OS packages, and how it spells that varies:
    # the literal "pkgdb" in the sample artifacts, but /var/lib/dpkg/status on a live
    # Ubuntu scan (235 of 237 findings landed on that single path), and /var/lib/rpm/*
    # elsewhere. Rather than hardcode sentinels that differ per distro and per
    # anchorectl version, find them in the data: any path covering more than one
    # package cannot identify a finding on its own.
    by_path = {}
    for v in vuln_data:
        by_path.setdefault(pick(v, "packagePath") or "NA", set()).add(pick(v, "packageName"))
    return set(p for p, names in by_path.items() if len(names) > 1)


def location_file(pkgpath, pkgname, shared):
    # Language packages already have a per-package path (a dist-info METADATA, a
    # go.sum) and pass through untouched; a shared path is qualified with the package
    # name so each finding gets a stable, distinct location.
    if not pkgpath or pkgpath == "NA":
        return pkgname
    if pkgpath in shared:
        return "{}/{}".format(pkgpath, pkgname)
    return pkgpath


def stable_vuln_key(vuln, vid):
    # F15: feeds re-attribute an advisory between systems (nvd -> github:python),
    # moving the primary id and re-filing the finding in GitLab. A CVE alias
    # survives that, so prefer it for the id hash only (display is unaffected).
    # Sorted: nvdData's order is not guaranteed by the API, so an advisory aliasing
    # several CVEs could return a different "first" CVE between two daily runs,
    # flipping the hash and re-filing the finding -- the churn F15 exists to prevent.
    cves = sorted(str(c).upper() for c in
                  (clean(nd.get("id")) for nd in (pick(vuln, "nvdData") or []))
                  if c and str(c).upper().startswith("CVE-"))
    return cves[0] if cves else vid


def _norm_ts(t):
    # F17: GitLab requires exactly yyyy-mm-ddThh:mm:ss in UTC. Accept trailing Z, a
    # numeric offset, fractional seconds or a space separator, and convert to UTC
    # rather than truncating (which would relabel an offset time as UTC).
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


def convert_to_sast(policy_data, vuln_data, image_data, allow, recs,
                    on_missing="fail", default_os="unknown"):
    os_value = operating_system(image_data, on_missing, default_os)      # F1
    image = image_ref(policy_data, image_data)
    if not image:
        die("could not determine image tag (evaluatedTag / imageDetail[0].fullTag) (F13)")
    start_time, end_time = scan_window(image_data)

    analyzer = {
        "id": "anchore-enterprise", "name": "Anchore Enterprise",
        "version": "enterprise", "vendor": {"name": "Anchore Inc."},
    }
    scan = {
        "analyzer": analyzer,
        "scanner": dict(analyzer),
        "start_time": start_time,
        "end_time": end_time,
        "status": "success",
        "type": "sast",
    }

    ret = []
    by_id = {}
    has_fix = {}
    shared_paths = shared_package_paths(vuln_data)
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

        if (vid, pkg) in allow or (vid, pkgname) in allow:
            omitted += 1
            continue

        sev = pick(vuln, "severity") or "unknown"
        gvsev = GITLAB_SEV.get(sev.lower(), "Unknown")   # F7

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

        extras = []
        feed = pick(vuln, "feedGroup")
        if feed:
            extras.append("feed {}".format(feed))
        if pick(vuln, "willNotFix"):
            extras.append("vendor will-not-fix")
        if vuln.get("inheritedFromBase") is not None:
            extras.append("inheritedFromBase={}".format(bool(vuln.get("inheritedFromBase"))))
        description = "There is a vulnerability {} detected in installed package {} ({}). See link for more information.".format(
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
            # F8: union identifiers/links into the existing finding rather than
            # emitting a colliding id.
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
            "message": "{} in {}".format(vid, pkg),
            "description": description,
            "severity": gvsev,
            "solution": solution,
            "scanner": {"id": "anchore-enterprise", "name": "anchore-enterprise"},
            "location": {
                # Without location.file the Vulnerability Report showed no file for
                # any entry and findings differing only by package could collapse
                # together. The container-scanning keys below are kept unchanged for
                # anyone already consuming them.
                "file": location_file(pkgpath, pkgname, shared_paths),
                "dependency": {"package": {"name": pkgname}, "version": pkgvers},
                "operating_system": os_value,        # F1
                "image": image,
            },
            "identifiers": identifiers,
            "links": links,
        }
        ret.append(record)
        by_id[vhash] = record
        has_fix[vhash] = bool(fixver)

    sys.stderr.write("sast: {} finding(s) omitted by allowlist\n".format(omitted))
    sys.stderr.write("sast: {} finding(s) merged into an existing identity (F8)\n".format(merged))
    return ret, scan




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
                    "SAST report (schema version {}).".format(GITLAB_SCHEMA_VERSION),
        epilog=(
            "schema validation (--validate):\n"
            "  The official GitLab SAST schema (version {ver}) is embedded in this script, so\n"
            "  validation needs no network and works airgapped. --validate checks the written\n"
            "  report against it and exits non-zero on any violation. It requires the 'jsonschema'\n"
            "  package (see requirements.txt) and ERRORS if that is not installed (it never\n"
            "  silently skips). Without --validate no validation runs and 'jsonschema' is not needed.\n\n"
            "inputs (from `anchorectl ... -o json`; camelCase or snake_case both accepted):\n"
            "  --vuln-data   `anchorectl image vulnerabilities`  (the finding set)\n"
            "  --eval-data   `anchorectl image check --detail`   (allowlist + recommendations)\n"
            "  --image-data  `anchorectl image get`              (OS distro + tag + scan times)\n"
        ).format(ver=GITLAB_SCHEMA_VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--vuln-data", required=True, help="anchorectl image vulnerabilities -o json")
    parser.add_argument("--eval-data", required=True, help="anchorectl image check --detail -o json")
    parser.add_argument("--image-data", required=True, help="anchorectl image get -o json (OS distro + tag + times)")
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
    vulnerabilities, scan = convert_to_sast(eval_data, vuln_data, image_data, allow, recs,
                                            args.on_missing_distro, args.default_os)

    report = dict(GITLAB_SAST_TEMPLATE)
    report["vulnerabilities"] = vulnerabilities
    report["scan"] = scan

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if args.validate or args.schema:
        validate_report(args.output, args.schema)


if __name__ == "__main__":
    main()
