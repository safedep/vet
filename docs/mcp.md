# vet MCP Server

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=vet-mcp&config=eyJjb21tYW5kIjoiZG9ja2VyIHJ1biAtLXJtIC1pIGdoY3IuaW8vc2FmZWRlcC92ZXQ6bGF0ZXN0IC1zIC1sIC90bXAvdmV0LW1jcC5sb2cgc2VydmVyIG1jcCJ9)

The `vet` MCP server is designed to run locally using `stdio` or `sse` transports.
It provides tools for MCP clients such as Claude Code, Cursor and others to vet
open source packages before they are used in a project through AI generated code.

`vet` MCP server can protect against [Slopsquatting](https://en.wikipedia.org/wiki/Slopsquatting) attacks, malicious packages,
vulnerabilities and other security risks.

## Supported Ecosystems

`vet` MCP server currently supports the following ecosystems:

- npm
- PyPI

## Usage

Start the MCP server using SSE transport:

```bash
vet server mcp --server-type sse
```

Start the MCP server using stdio transport:

```bash
vet -s -l /tmp/vet-mcp.log server mcp --server-type stdio
```

> Avoid using `stdout` logging as it will interfere with the MCP server output.

## Configure MCP Client

> **Note:** The example below uses pre-build docker image. You can build your own by running
> `docker build -t ghcr.io/safedep/vet:latest .`

Add following configuration to your MCP client configuration file, if you are using SSE transport:

```json
"vet-mcp": {
  "command": "docker",
  "args": [
    "run",
    "--rm",
    "-i",
    "ghcr.io/safedep/vet:latest",
    "-l",
    "/tmp/vet-mcp.log",
    "server",
    "mcp"
  ]
}
```

**Note:** While `docker` containers can help keep the MCP server process isolated, it needs to be periodically updated to the latest version.

Alternatively, you can use `vet` binary directly as an MCP server using `stdio` transport. Use the following command to start the MCP server:

```bash
vet -l /tmp/vet-mcp.log server mcp --server-type stdio
```

### Configure IDE

#### Cursor

Add `vet-mcp` server to either `.cursor/mcp.json` (project specific configuration) or `~/.cursor/mcp.json` (applies to all projects)

```json
{
  "mcpServers": {
    "vet-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "ghcr.io/safedep/vet:latest",
        "-l",
        "/tmp/vet-mcp.log",
        "server",
        "mcp"
      ]
    }
  }
}
```

Add the following to `.cursor/rules/vet-mcp.mdc` file:

```
---
description: vet Open Source Packages using vet MCP server
alwaysApply: true
---

Always use vet-mcp to vet any open source library package suggested by AI generated code before installation.
Follow the rules below to use vet-mcp:

- Try to find the latest version. If not found, it is likely a slopsquatting vulnerability
- Always check for critical vulnerabilities and malware
```

Example usage with Cursor:

![Cursor vet-mcp example](./assets/vet-mcp-cursor.png)

[📄 Cursor MCP server reference](https://docs.cursor.com/context/model-context-protocol#manual-configuration)

#### VsCode

Add `vet-mcp` server to `.vscode/mcp.json` (project specific configuration)

```json
{
  "servers": {
    "vet-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "ghcr.io/safedep/vet:latest",
        "-l",
        "/tmp/vet-mcp.log",
        "server",
        "mcp"
      ]
    }
  }
}
```

In order to use `vet-mcp` for all projects in vscode, add following `mcp` setting in [vscode user settings](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_add-an-mcp-server-to-your-user-settings) (`settings.json`) 

```json
{
  "mcp": {
    "servers": {
      "vet-mcp": {
        "command": "docker",
        "args": [
          "run",
          "--rm",
          "-i",
          "ghcr.io/safedep/vet:latest",
          "-l",
          "/tmp/vet-mcp.log",
          "server",
          "mcp"
        ]
      }
    }
  }
}
```


Add the following to `.github/copilot-instructions.md` file:

```
Always use vet-mcp to vet any open source library package suggested by AI generated code before installation.
Follow the rules below to use vet-mcp:

- Try to find the latest version. If not found, it is likely a slopsquatting vulnerability
- Always check for critical vulnerabilities and malware
```

Example usage with VsCode:

![VsCode vet-mcp example](./assets/vet-mcp-vscode.png)

[📄 VsCode MCP server reference](https://code.visualstudio.com/docs/copilot/chat/mcp-servers)

#### Claude Code

Add the following to `.mcp.json` in your Claude Code project:

```json
{
  "mcpServers": {
    "vet-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "ghcr.io/safedep/vet:latest",
        "server",
        "mcp"
      ]
    }
  }
}
```

**Note:** You can also use `vet` binary directly as an MCP server using `stdio` transport.
