---
sidebar_position: 2
title: 🏄 Code Analysis
---

# Code Analysis

:::note

EXPERIMENTAL: This feature is experimental and may introduce breaking changes.

:::

`vet` has a code analysis framework built on top of [tree-sitter](https://tree-sitter.github.io/tree-sitter/) parsers. The goal
of this framework is to support multiple languages, source repositories (local and remote),
and create a representation of code that can be analysed for common software
supply chain security related use-cases such as

- Identify shadowed imports
- Identify evidence of a dependency actually being used
- Import reachability analysis
- Function reachability analysis

:::warning

The code analysis framework is designed specifically to be simple, fast and
not to be a full-fledged static analysis tool. It is currently in early stages
of development and may not support all languages or maintain API compatibility.

:::

## Build a Code Analysis Database

- Analyse code and build a database for further analysis.

```bash
vet code --db /tmp/code.db \
    --src /path/to/app \
    --imports /virtualenvs/app/lib/python3.11/site-packages \
    --lang python \
    create-db
```

The above command does the following:

- Uses Python as the language for parsing source code
- Analyses application code recursively in `/path/to/app`
- Analyses dependencies in `/virtualenvs/app/lib/python3.11/site-packages`
- Creates a database at `/tmp/code.db` for further analysis

## Manual Query Execution

Use [cayleygraph](https://cayley.gitbook.io/cayley/) to query the database.

```bash
docker run -it -p 64210:64210 -v /tmp/code.db:/db cayleygraph/cayley -a /db -d bolt
```

- Navigate to `http://127.0.0.1:64210` in your browser

### Query Examples

#### Dependency Graph

Build dependency graph for your application

```js
g.V().Tag("source").out("imports").Tag("target").all()
```

![Dependency Graph](/img/vet-code-demo-import-graph.png)

#### Import Reachability

Check if a specific import is reachable in your application

```js
g.V("app").followRecursive(g.M().out("imports")).is("six").all()
```

- `app` is the application originating from `app.py`
- `six` is a python module imported transitively

### Query API

Refer to [Gizmo Query Language](https://cayley.gitbook.io/cayley/query-languages/gizmoapi)
for documentation on constructing custom queries.
