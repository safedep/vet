# vet MCP Server

The `vet` MCP server is designed to run locally using `stdio` or `sse` transports.
It provides tools for MCP clients such as Claude Code, Cursor and others to vet
open source packages before they are used in a project through AI generated code.

`vet` MCP server can protect against [Slopsquatting](#) attacks, malicious packages,
vulnerabilities and other security risks.

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

Add following configuration to your MCP client if you are using SSE transport:

```json
{
  "mcpServers": {
    "vet-mcp": {
      "url": "http://localhost:9988/sse"
    }
  }
}
```
