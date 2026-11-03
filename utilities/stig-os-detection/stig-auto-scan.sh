#!/usr/bin/env bash
#
# stig-auto-scan.sh - detect an image's OS via Anchore Enterprise and run the
# matching STIG profile with anchorectl. Intended for CI pipelines.
#
# Usage: stig-auto-scan.sh [options] IMAGE
#   IMAGE  registry/repo:tag (optionally @sha256:digest)
#
# Requires: anchorectl (configured via ANCHORECTL_URL/USERNAME/PASSWORD or
# config file), jq, and a docker (or podman-shimmed docker) daemon.

set -euo pipefail

ANCHORECTL="${ANCHORECTL:-anchorectl}"
PROFILE_DIR="${STIG_PROFILE_DIR:-}"
OUTPUT_DIR="${STIG_OUTPUT_DIR:-}"
SKIP_ADD=false
SKIP_UPLOAD=false
DRY_RUN=false
ALLOW_RHEL_CLONES=false
UNSUPPORTED_EXIT=2
FAIL_ON_FINDINGS="${STIG_FAIL_THRESHOLD:-}"
EXTRA_INPUTS=()
WAIVERS=()
EXTRA_ARGS=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] IMAGE

Detects the OS of IMAGE from Anchore Enterprise image metadata and runs the
applicable STIG profile via 'anchorectl stig docker image execute'.

  rhel 8.x      -> rhel8          ubuntu 22.04 -> ubuntu2204
  rhel 9.x      -> rhel9          ubuntu 24.04 -> ubuntu2404
  wolfi/chainguard -> chainguard

Options:
  -d, --profile-dir DIR     directory of STIG profiles laid out like
                            'anchorectl stig write-profiles' output
                            (default: write the bundled profiles to a temp dir)
                            env: STIG_PROFILE_DIR
  -o, --output-dir DIR      save STIG evaluation results here (env: STIG_OUTPUT_DIR)
  -i, --input-file FILE     extra profile input file (repeatable; the profile's
                            bundled profile-inputs.yaml is always included)
  -w, --waiver-file FILE    STIG waiver file (repeatable)
      --fail-threshold N    exit 3 if more than N controls fail (requires
                            --output-dir; env: STIG_FAIL_THRESHOLD)
      --skip-add            don't submit the image for analysis; it must already
                            be analyzed in Anchore
      --skip-upload         don't upload the evaluation to Anchore
      --allow-rhel-clones   treat centos/rocky/almalinux/ol as rhel
      --skip-unsupported    exit 0 (instead of 2) when no profile matches the OS
      --dry-run             detect the OS and print the command without running it
  -h, --help                show this help

Any arguments after '--' are passed through to 'anchorectl stig docker image execute'
(e.g. -- --stig-tools-image docker.io/library/busybox:musl).

Exit codes: 0 success, 1 error, 2 no STIG profile for the detected OS,
            3 failed controls exceed --fail-threshold.
EOF
}

log() { echo "[stig-auto-scan] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

IMAGE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--profile-dir)     PROFILE_DIR="$2"; shift 2 ;;
    -o|--output-dir)      OUTPUT_DIR="$2"; shift 2 ;;
    -i|--input-file)      EXTRA_INPUTS+=("$2"); shift 2 ;;
    -w|--waiver-file)     WAIVERS+=("$2"); shift 2 ;;
    --fail-threshold)     FAIL_ON_FINDINGS="$2"; shift 2 ;;
    --skip-add)           SKIP_ADD=true; shift ;;
    --skip-upload)        SKIP_UPLOAD=true; shift ;;
    --allow-rhel-clones)  ALLOW_RHEL_CLONES=true; shift ;;
    --skip-unsupported)   UNSUPPORTED_EXIT=0; shift ;;
    --dry-run)            DRY_RUN=true; shift ;;
    -h|--help)            usage; exit 0 ;;
    --)                   shift; EXTRA_ARGS=("$@"); break ;;
    -*)                   usage >&2; die "unknown option: $1" ;;
    *)                    [[ -z "$IMAGE" ]] || die "only one IMAGE may be given"; IMAGE="$1"; shift ;;
  esac
done

[[ -n "$IMAGE" ]] || { usage >&2; exit 1; }
[[ -z "$FAIL_ON_FINDINGS" || -n "$OUTPUT_DIR" ]] || die "--fail-threshold requires --output-dir"
command -v jq >/dev/null || die "jq is required"
command -v "$ANCHORECTL" >/dev/null || die "anchorectl not found (set ANCHORECTL=/path/to/anchorectl)"

# 1. Make sure Anchore has analyzed the image so OS metadata is available.
if [[ "$SKIP_ADD" == false ]]; then
  log "submitting $IMAGE for analysis and waiting for completion"
  "$ANCHORECTL" image add "$IMAGE" --wait >&2
fi

# 2. Pull OS metadata and digest from Anchore.
image_json="$("$ANCHORECTL" image get "$IMAGE" -o json)" \
  || die "could not get image $IMAGE from Anchore (is it analyzed? try without --skip-add)"

status="$(jq -r '.analysisStatus' <<<"$image_json")"
[[ "$status" == "analyzed" ]] || die "image analysis status is '$status', expected 'analyzed'"

distro="$(jq -r '.imageContent.metadata.distro // empty' <<<"$image_json" | tr '[:upper:]' '[:lower:]')"
distro_version="$(jq -r '.imageContent.metadata.distroVersion // empty' <<<"$image_json")"
digest="$(jq -r '.imageDigest' <<<"$image_json")"
log "detected OS: ${distro:-unknown} ${distro_version:-unknown} (digest $digest)"

# 3. Map OS -> STIG profile.
major="${distro_version%%.*}"
if [[ "$ALLOW_RHEL_CLONES" == true ]]; then
  case "$distro" in centos|rocky|almalinux|ol) distro=rhel ;; esac
fi

profile=""
case "$distro" in
  rhel)
    case "$major" in
      8) profile=rhel8 ;;
      9) profile=rhel9 ;;
    esac ;;
  ubuntu)
    case "$distro_version" in
      22.04*) profile=ubuntu2204 ;;
      24.04*) profile=ubuntu2404 ;;
    esac ;;
  wolfi|chainguard)
    profile=chainguard ;;
esac

if [[ -z "$profile" ]]; then
  log "no STIG profile available for '${distro:-unknown} ${distro_version:-unknown}'"
  exit "$UNSUPPORTED_EXIT"
fi
log "selected STIG profile: $profile"

# 4. Locate the profile (bundled with anchorectl unless a directory was supplied).
if [[ -z "$PROFILE_DIR" ]]; then
  PROFILE_DIR="$(mktemp -d)"
  trap 'rm -rf "$PROFILE_DIR"' EXIT
  "$ANCHORECTL" stig write-profiles "$PROFILE_DIR" >&2
fi
profile_archive="$PROFILE_DIR/$profile/$profile.tar.gz"
profile_inputs="$PROFILE_DIR/$profile/profile-inputs.yaml"
[[ -e "$profile_archive" ]] || die "profile not found: $profile_archive"

# 5. Build a fully qualified name:tag@digest reference, as required by execute.
ref="${IMAGE%@*}"
if [[ "$ref" == sha256:* || "${ref##*/}" != *:* ]]; then
  # input had no tag (bare repo or repo@digest) - use the tag Anchore knows about
  tagged="$(jq -r '.imageDetail[0].fullTag // empty' <<<"$image_json")"
  [[ -n "$tagged" ]] && ref="$tagged"
fi
target="${ref}@${digest}"

cmd=("$ANCHORECTL" stig docker image execute "$target" -p "$profile_archive")
[[ -f "$profile_inputs" ]] && cmd+=(-i "$profile_inputs")
for f in ${EXTRA_INPUTS[@]+"${EXTRA_INPUTS[@]}"}; do cmd+=(-i "$f"); done
for f in ${WAIVERS[@]+"${WAIVERS[@]}"}; do cmd+=(--stig-waiver-file "$f"); done
[[ -n "$OUTPUT_DIR" ]] && { mkdir -p "$OUTPUT_DIR"; cmd+=(--stig-output-dir "$OUTPUT_DIR"); }
[[ "$SKIP_UPLOAD" == true ]] && cmd+=(--stig-skip-upload)
cmd+=(${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})

log "running: ${cmd[*]}"
if [[ "$DRY_RUN" == true ]]; then
  exit 0
fi

# 6. Run the STIG evaluation, summarize, and show what was recorded in Anchore.
"${cmd[@]}"

if [[ -n "$OUTPUT_DIR" ]]; then
  result_file="$(ls -t "$OUTPUT_DIR"/*.json 2>/dev/null | head -1)"
  if [[ -n "$result_file" ]]; then
    summary="$(jq -c '[.profiles[-1].controls[] | (.results | map(.status)) as $s
      | if any($s[]; . == "failed") then "failed"
        elif ($s | length) > 0 and all($s[]; . == "skipped") then "skipped"
        else "passed" end]
      | {passed: map(select(. == "passed")) | length,
         failed: map(select(. == "failed")) | length,
         skipped: map(select(. == "skipped")) | length}' "$result_file")"
    log "control summary ($profile): $summary  [$result_file]"
    failed="$(jq -r '.failed' <<<"$summary")"
    if [[ -n "$FAIL_ON_FINDINGS" && "$failed" -gt "$FAIL_ON_FINDINGS" ]]; then
      log "$failed failed controls exceeds threshold of $FAIL_ON_FINDINGS"
      exit 3
    fi
  fi
fi

if [[ "$SKIP_UPLOAD" == false ]]; then
  "$ANCHORECTL" stig docker image list "$target" || true
fi
