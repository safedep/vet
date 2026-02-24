/**
 * Test fixture for JavaScript capability detection.
 * This file exercises various Node.js standard library functions
 * across different capability categories.
 */

const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const child_process = require('child_process');
const sqlite3 = require('sqlite3');

function testFilesystemOperations() {
  // Filesystem write
  fs.writeFileSync('test.txt', 'hello');

  // Filesystem read
  fs.readFileSync('test.txt');

  // Filesystem delete
  fs.unlinkSync('test.txt');

  // Filesystem mkdir
  fs.mkdirSync('testdir');
}

function testNetworkOperations() {
  // HTTP client
  http.get('https://example.com', (res) => {
    console.log('Response received');
  });

  // HTTP server
  const server = http.createServer((req, res) => {
    res.end('Hello World');
  });
}

function testEnvironmentOperations() {
  // Environment write
  process.env.TEST = 'value';

  // Environment read
  const home = process.env.HOME;
  console.log(home);
}

function testProcessOperations() {
  // Process execution
  child_process.exec('ls -la', (error, stdout, stderr) => {
    console.log(stdout);
  });

  // Process info
  const pid = process.pid;
  console.log(pid);
}

function testCryptoOperations() {
  // Hash operations - SHA256
  const hash = crypto.createHash('sha256');
  hash.update('data');
  hash.digest('hex');

  // Hash operations - MD5
  const md5 = crypto.createHash('md5');
  md5.update('test');
  md5.digest('hex');
}

function testDatabaseOperations() {
  // SQLite database
  const db = new sqlite3.Database(':memory:');

  // Execute query
  db.run('CREATE TABLE test (id INTEGER, name TEXT)');

  db.close();
}

// Main execution
testFilesystemOperations();
testNetworkOperations();
testEnvironmentOperations();
testProcessOperations();
testCryptoOperations();
testDatabaseOperations();
