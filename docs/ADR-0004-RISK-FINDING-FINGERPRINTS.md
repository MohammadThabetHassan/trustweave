# ADR-0004: Risk Finding Fingerprint Identity

## Status

Accepted for `trustweave/fingerprint/v3`.

## Context

Risk baselines and suppressions refer to a canonical local finding across policy, trace, MCP-profile, bundle-diff, and declared-chain review artifacts. The identity must remain deterministic and local while distinguishing semantically different declared subjects. Review wording, artifact locations, and rendered output should not create a new decision identity.

## Decision

TrustWeave computes a SHA-256 fingerprint over canonical JSON containing the fingerprint schema version, evidence kind, finding identifier, and stable subject. Legacy `review` severity is normalized to `medium` as a separate reviewer-visible severity property, but severity is not fingerprint material. Human-readable messages, local artifact paths, baseline reasons, output directories, timestamps, and report formatting are not fingerprint material.

Subject strings remain scalar. Sequence metadata is normalized as an unordered set except for `path`, which remains an ordered immutable tuple because it represents a declared traversal. Consequently, a reversed or otherwise reordered declared chain path has a distinct fingerprint. Canonical finding and risk-normalization models defensively freeze mappings and nested sequences before exposing them to callers; public JSON rendering converts frozen sequences back to arrays.

## Consequences

A wording correction or severity change does not invalidate a reviewed local decision when the stable subject is unchanged. A distinct declared path does not inherit a baseline or suppression intended for a different route. Fingerprints identify supplied local evidence only: they do not authenticate an approver, prove deployed behavior, resolve a finding, or establish a runtime security condition.
