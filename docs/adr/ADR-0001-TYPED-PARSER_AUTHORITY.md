# ADR-0001: Typed Parser Authority and Schema Conformance

## Status

Accepted for the `v1alpha1` local evidence contracts.

## Context

TrustWeave publishes JSON Schemas for editor feedback and interoperability, while its local Python parsers enforce semantic constraints such as cross-reference validity, duplicate identifiers, first-class enum errors, and privacy-preserving trace handling. Running a separate JSON Schema implementation in every user workflow would add a core runtime dependency without replacing the semantic parser.

## Decision

The typed parser is the authoritative runtime contract. Every supported object rejects unknown fields by default and reports the precise document path. Close field names receive a deterministic suggestion when one is available.

Published JSON Schemas remain the structural source used by editors and external tooling. CI validates every checked-in manifest, policy, trace, and MCP profile fixture against its corresponding Draft 2020-12 schema, then validates the same fixture through the typed parser. Contract-hardening tests also prove that representative unknown fields are rejected by both layers.

Raw tool arguments and JSON Schema payloads remain opaque data fields. TrustWeave validates only their declared outer object shape and does not inspect, copy, evaluate, or execute their content.

## Consequences

This preserves the project’s zero-required-runtime-dependency posture while preventing silent schema/parser drift in CI. A contract change must update the typed parser, the published schema where one exists, positive and negative fixtures, conformance tests, the CLI reference, and the compatibility notes.

> This decision does not claim standards-compliant runtime JSON Schema validation for every local command. It defines a deliberately strict typed runtime parser, with published-schema conformance checked in the development and CI workflow.
