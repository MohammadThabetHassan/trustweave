# ADR-0003: Embedded Finding Versioning

## Status

Accepted.

## Context

TrustWeave review artifacts contain canonical local findings. The original finding schema required a `schema_version` on each embedded finding, while the runtime serializer intentionally emits only the containing artifact’s version. That mismatch meant the published contract did not validate actual local evidence.

## Decision

A finding embedded in a versioned TrustWeave artifact **inherits its version from its containing artifact**. The v1alpha1 finding schema therefore does not require or permit a repeated `schema_version` field. Its schema models the emitted fields directly, including bounded structured `subject`, optional `location`, `references`, and safe structured `properties`.

A subject value is either one bounded string or a bounded one-dimensional string sequence. The `path` subject is ordered because its sequence represents a declared traversal; other sequence metadata is normalized deterministically. Locations and references permit bounded string maps only. Properties additionally permit booleans and non-negative bounded integers for local analysis counters. Arbitrary nested objects, arrays of objects, unbounded values, and caller-owned mutable mappings or sequences are rejected or defensively frozen before serialization.

The surrounding artifact remains responsible for declaring the applicable finding-contract version. A future standalone finding document, if introduced, will use its own explicit envelope schema rather than changing this embedded contract.

## Consequences

Runtime serializers, local risk normalization, Markdown renderers, and SARIF conversion consume the same embedded canonical shape. Built-in producers route their review observations through the shared canonical finding builder rather than maintaining producer-specific field shapes. This decision avoids per-finding version noise while preserving deterministic, versioned artifact boundaries. It does not make a local review finding a runtime security verdict, an authorization decision, or proof of deployed behavior.
