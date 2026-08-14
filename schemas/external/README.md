# External schema resources

## SARIF 2.1.0

`sarif-schema-2.1.0.json` is the unmodified OASIS SARIF 2.1.0 errata-01 schema used only by local test-time conformance validation. Its source is:

<https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>

The pinned file has SHA-256:

```text
c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
```

TrustWeave does not load this external schema at runtime, fetch it over a network, publish SARIF, or claim a certification. The test suite validates generated local JSON against this checked-in resource so exporter conformance changes are explicit and reviewable.
