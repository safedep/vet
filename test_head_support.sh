#!/bin/bash

# Simple script to test HEAD request functionality
# This creates a minimal test server and verifies HEAD requests work

set -e

echo "Building test binary..."
go build -o /tmp/vet-test

echo "Starting server in background..."
/tmp/vet-test -s server mcp --server-type sse --sse-server-addr localhost:19999 &
SERVER_PID=$!

# Give server time to start
sleep 2

echo "Testing HEAD request to SSE endpoint..."
response=$(curl -I -s -w "HTTP_CODE:%{http_code}" http://localhost:19999/sse)

echo "Response received:"
echo "$response"

# Check if we got 200 status code
if echo "$response" | grep -q "HTTP_CODE:200"; then
    echo "✅ HEAD request test PASSED - received 200 status"
else
    echo "❌ HEAD request test FAILED - did not receive 200 status"
    echo "Killing server..."
    kill $SERVER_PID
    exit 1
fi

# Check if we got the expected SSE headers
if echo "$response" | grep -q "text/event-stream"; then
    echo "✅ Content-Type header test PASSED"
else
    echo "❌ Content-Type header test FAILED"
    echo "Killing server..."
    kill $SERVER_PID
    exit 1
fi

if echo "$response" | grep -q "no-cache"; then
    echo "✅ Cache-Control header test PASSED"
else
    echo "❌ Cache-Control header test FAILED"
    echo "Killing server..."
    kill $SERVER_PID
    exit 1
fi

echo "✅ All HEAD request tests PASSED!"

echo "Killing server..."
kill $SERVER_PID

echo "Test completed successfully!"