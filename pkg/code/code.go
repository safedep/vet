package code

// Things that we can do
// 1. Prune unused direct dependencies based on code usage
// 2. Find places in 1P code where a vulnerable library is imported
// 3. Find places in 1P code where a call to a vulnerable function is made
// 4. Find path from 1P code to a vulnerable function in direct or transitive dependencies
// 5. Find path from 1P code to a vulnerable library in direct or transitive dependencies

// Primitives that we need
// 1. Source code parsing
// 2. Import resolution to local 1P code or imported files in 3P code
// 3. Graph datastructure to represent a function call graph across 1P and 3P code
// 4. Graph datastructure to represent a file import graph across 1P and 3P code
//
// Source code parsing should provide
// 1. Enumerate imported 3P code
// 2. Enumerate functions in the source code
// 3. Enumerate function calls to 1P or 3P code
//
// Code Property Graph (CPG), stitching 1P and 3P code
// into a queryable graph datastructure for analyzers having
//
// Future enhancements should include ability to enrich function nodes
// with meta information such as contributors, last modified time, use-case tags etc.

// CONCEPTS used in building the framework
// 1. Source: Used to represent a mechanism to find and enumerate source files
// 2. Language: Used to represent the domain of programming languages
// 3. Node: Used to represent an in-memory representation of a node in an AST / CST
// 4. Entity: Used to represent a node that can be persisted in a property graph (analysis and query domain)
