# ---------------------------------------------------------------------------
# Part of the Anchore Examples Repository.
# Licensed under the Apache License, Version 2.0 (the "License").
#
# THIS SCRIPT IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR 
# CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
# ---------------------------------------------------------------------------

#!/bin/bash



#Uses your anchorectl variables to export the description of vulnerabilities for a given image in JSON format.


#pass in the image name to the command below
IMAGE_CHECK=$(anchorectl image check docker.io/notify:1.0 2>/dev/null | grep "Digest:" | awk '{print $2}')

curl -u "admin:foobar" "$ANCHORECTL_USERNAME:$ANCHORECTL_PASSWORD" -X GET "$ANCHORECTL_URL/v2/images/$IMAGE_CHECK/vuln/all/cyclonedx-json?force_refresh=false&include_vuln_description=true&include_annotation_detail=true&vendor_only=true" -H \
  -H 'accept: application/json' | \
  jq '[.vulnerabilities[] | 
    .id as $cve | 
    .description as $desc |
    # Hunt for the CVSS score across different possible methods
    ((.ratings[] | select(.method == "CVSSv3" or .method == "CVSSv31").score) // 
     (.ratings[] | select(.method == "CVSSv2").score) // 
     .ratings[0].score // 0) as $score |
    (.ratings[0].severity // "unknown") as $sev | 
    .affects[] | .ref as $ref | .versions[] | {
      score: $score,
      severity: $sev,
      cve: $cve,
      package: $ref,
      version: .version,
      status: .status,
      description: $desc
    }
  ] | sort_by(.score) | reverse'
