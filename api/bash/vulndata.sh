#!/bin/bash

# ---------------------------------------------------------------------------
# Part of the Anchore Examples Repository.
# Licensed under the Apache License, Version 2.0 (the "License").
#
# THIS FILE IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
# ---------------------------------------------------------------------------

# --- Configuration ---
# put variables for username, password, and Anchore_URL in anchore.env file
if [ -f ./anchore.env ]; then
    source ./anchore.env
else
    echo "Error: anchore.env file not found."
    exit 1
fi

#GITLAB you can use $CI_PROJECT NAME for app_name
#I would use a git tag for target version
APP_NAME="rust"
TARGET_VERSION="2.0"

echo "Step 1: Fetching IDs for $APP_NAME version $TARGET_VERSION..."

# --- Step 1 & 2: Get Application and Version IDs ---
# We fetch the list and use the jq logic we built earlier to grab both IDs at once
read -r APP_ID VER_ID <<< $(curl -s -u "$USERNAME:$PASSWORD" "$ANCHORE_URL/applications?include_versions=true" -H 'accept:application/json' | \
jq -r --arg NAME "$APP_NAME" --arg VER "$TARGET_VERSION" '
  .[] | 
  select(.name == $NAME) | 
  .application_id as $a | 
  .application_versions[] | 
  select(.version_name == $VER) | 
  "\($a) \(.application_version_id)"')

# Validate we actually found the IDs
if [[ -z "$APP_ID" || -z "$VER_ID" ]]; then
    echo "Error: Could not find $APP_NAME version $TARGET_VERSION"
    exit 1
fi

echo "Found App ID: $APP_ID"
echo "Found Version ID: $VER_ID"

# --- Step 3: Fetch Vulnerabilities ---
echo "Step 2: Fetching Vulnerability Data..."

# The endpoint for vulnerabilities usually follows this pattern in Anchore Enterprise
VULN_DATA=$(curl -s -u "$USERNAME:$PASSWORD" \
    "$ANCHORE_URL/applications/$APP_ID/versions/$VER_ID/vulnerabilities" -H 'accept:application/json')

# --- Final Step: Output results ---
# Print the results in a clean table format (Severity and CVE ID)
echo "--------------------------------------------------------"
echo "Vulnerability Report for $APP_NAME $TARGET_VERSION"
echo "--------------------------------------------------------"
echo "$VULN_DATA" | jq -r '.vulnerabilities[] | .nvd[] | "\(.id): \(.description)\n"' | tee vulndata
