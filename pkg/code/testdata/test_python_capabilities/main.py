"""
Test fixture for Python capability detection.
This file exercises various Python standard library functions
across different capability categories.
"""

import os
import hashlib
import subprocess
import sqlite3
from urllib.request import urlopen
from pathlib import Path

def test_filesystem_operations():
    """Test filesystem capability detection"""
    # Filesystem read
    with open("test.txt", "r") as f:
        f.read()

    # Filesystem write
    with open("test.txt", "w") as f:
        f.write("hello")

    # Filesystem delete
    os.remove("test.txt")

    # Filesystem mkdir
    os.mkdir("testdir")

    # Pathlib operations
    p = Path("test.txt")
    p.read_text()
    p.write_text("content")

def test_network_operations():
    """Test network capability detection"""
    # HTTP client
    urlopen("https://example.com")

    # Socket operations would require additional imports
    # but urllib.request.urlopen covers HTTP client

def test_environment_operations():
    """Test environment variable operations"""
    # Environment read
    os.getenv("HOME")

    # Environment write
    os.environ["TEST"] = "value"

def test_process_operations():
    """Test process execution and info"""
    # Process execution
    subprocess.run(["ls", "-la"])

    # Process info
    os.getpid()

def test_crypto_operations():
    """Test cryptographic operations"""
    # Hash operations
    hashlib.sha256(b"data").digest()

    # MD5 hash
    hashlib.md5(b"test").digest()

def test_database_operations():
    """Test database operations"""
    # SQLite database
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE test (id INTEGER)")
    conn.close()

if __name__ == "__main__":
    test_filesystem_operations()
    test_network_operations()
    test_environment_operations()
    test_process_operations()
    test_crypto_operations()
    test_database_operations()
