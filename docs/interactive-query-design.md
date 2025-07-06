# Agentic Interactive Query

## Overview

This document outlines the design for an **agentic interactive query system** for `vet` that enables users to explore data collected by `vet scan` through natural language conversations. As a design decision, we will take an agentic approach towards the query system and build upon the existing MCP tooling infrastructure in `vet` to provide the agent access to vet's data sources.

## Problem Statement

While `vet` provides powerful analysis capabilities through CEL filtering and MCP tools, users face several challenges:

1. **Capability Discovery**: Users don't know what analysis capabilities are available
2. **Complex Workflows**: Multi-step security analysis requires chaining multiple tools manually  
3. **Context Switching**: Users must switch between different commands and output formats
4. **Security Expertise**: Interpreting security data requires domain knowledge
5. **Insight Generation**: Raw data needs to be analyzed for actionable recommendations

An agentic system would enable users to have natural conversations like:

- "How secure are my dependencies?" → Agent analyzes vulnerabilities, malware, licenses, and popularity
- "Should I update package X?" → Agent checks for updates, vulnerability fixes, and breaking changes
- "What's the security posture of my project?" → Agent performs comprehensive multi-dimensional analysis
- "Are there any supply chain risks?" → Agent examines malware, suspicious packages, and dependency chains

## User Interface

```bash
# Start interactive agent session
vet query --from ./scan-data --agent

# Agent with specific LLM provider
vet query --from ./scan-data --agent --llm openai --model gpt-4o-mini

# Single question mode
vet query --from ./scan-data --agent --ask "How secure are my dependencies?"
```

## Design

### Command

`vet` query command will be extended to support the `agent` workflow. It is essentially a command of its own
that is responsible for:

1. Bootstrap the MCP server
2. Bootstrap the agent and its memory
3. Execute a single query or start conversation loop
4. Execute queries using the agent
5. Render the results using a format suitable for the response

### Agent

The agent is the core component of the query system. It is responsible for:

- Understanding the user's query
- Planning steps to execute in order to answer the query
- Use available MCP tools to gather required data
- Provide answer along with formatting hints

### Memory

The agent will have access to memory. The memory is bound within an agent session. 