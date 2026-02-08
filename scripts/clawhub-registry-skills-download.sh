#!/bin/bash

set -euo pipefail

# Download all skills from the ClawHub registry as zip archives.
# Usage: ./clawhub-registry-skills-download.sh <download-directory>

CLAWHUB_API_BASE="https://clawhub.ai"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <download-directory>"
    exit 1
fi

download_dir="$1"

if ! mkdir -p "$download_dir"; then
    echo "Failed to create download directory: $download_dir"
    exit 1
fi

success_log="$download_dir/success.log"
failure_log="$download_dir/failure.log"
: > "$success_log"
: > "$failure_log"

# Enumerate all skill slugs via paginated API
echo "Enumerating skills from ClawHub registry..."
slugs=()
cursor=""

while true; do
    url="$CLAWHUB_API_BASE/api/v1/skills"
    if [ -n "$cursor" ]; then
        url="$url?cursor=$cursor"
    fi

    response=$(curl -sSL "$url")

    page_slugs=$(echo "$response" | jq -r '.items[].slug')
    for slug in $page_slugs; do
        slugs+=("$slug")
    done

    cursor=$(echo "$response" | jq -r '.nextCursor // empty')
    if [ -z "$cursor" ]; then
        break
    fi
done

echo "Found ${#slugs[@]} skills"

# Download each skill zip
success_count=0
failure_count=0

for slug in "${slugs[@]}"; do
    output_file="$download_dir/${slug}.zip"
    echo "Downloading: $slug"

    if curl -sSL -f -o "$output_file" "$CLAWHUB_API_BASE/api/v1/download?slug=$slug"; then
        echo "$slug" >> "$success_log"
        success_count=$((success_count + 1))
    else
        echo "Failed to download: $slug"
        echo "$slug" >> "$failure_log"
        failure_count=$((failure_count + 1))
        rm -f "$output_file"
    fi
done

echo ""
echo "Download complete: $success_count succeeded, $failure_count failed"
echo "Success log: $success_log"
echo "Failure log: $failure_log"
