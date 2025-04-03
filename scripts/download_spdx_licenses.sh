#!/bin/bash

# Download SPDX license list from https://spdx.org/licenses/licenses.json to pkg/reporter/data/licenses.json
OUTPUT_FILE="$(dirname "$0")/../pkg/reporter/data/licenses.json"
echo "Downloading SPDX license list to: $OUTPUT_FILE"

curl -sSL https://spdx.org/licenses/licenses.json -o "$OUTPUT_FILE"

if [ $? -ne 0 ]; then
    echo "Failed to download SPDX license list"
    exit 1
fi

# Check if the file is valid JSON
if ! jq empty "$OUTPUT_FILE" > /dev/null 2>&1; then
    echo "Downloaded file is not valid JSON"
    exit 1
fi
echo "SPDX license list downloaded and validated successfully"
