# TrustWeave 0.3.0 Release Evidence

This record documents observed publication and package-provenance checks for the exact `v0.3.0` release tag. It is evidence for the named distribution files only; it does not certify TrustWeave, deployed agent systems, future releases, runtime enforcement, or attack prevention.

| Item | Observed value |
| --- | --- |
| Release tag | [`v0.3.0`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.3.0) |
| Tagged commit | `30308f47e84025315de2083047039e7efe0fd0ae` |
| TestPyPI trusted-publishing workflow | [run 32355879733](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32355879733), completed successfully |
| PyPI trusted-publishing workflow | [run 32356558687](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32356558687), completed successfully |
| Hosted assurance gates on tag target | [CI](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32354127973), [CodeQL](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32354128010), [mutation quality](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32354127994), and dependency graph all completed successfully |
| GitHub Release | [TrustWeave 0.3.0](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.3.0) |
| Expected publisher repository | `https://github.com/MohammadThabetHassan/trustweave` |

## TestPyPI exact-file verification

The TestPyPI wheel was published at:

```text
https://test-files.pythonhosted.org/packages/cb/72/622c0871cef3dbc4943964e887d21d9cd759beb9ff33a5cd2e24f595c277/trustweave-0.3.0-py3-none-any.whl
```

Its observed SHA-256 is:

```text
49be9adcc07a18b4743b19c2662aa852ccecdac9e8136af8bf9f2366213a846c
```

The TestPyPI Integrity API returned a provenance object at:

```text
https://test.pypi.org/integrity/trustweave/0.3.0/trustweave-0.3.0-py3-none-any.whl/provenance
```

That provenance verified against expected publisher repository `https://github.com/MohammadThabetHassan/trustweave` with the exact downloaded wheel and local provenance object. The following command returned `OK: trustweave-0.3.0-py3-none-any.whl`:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  --provenance-file trustweave-0.3.0-py3-none-any.whl.provenance \
  trustweave-0.3.0-py3-none-any.whl
```

After TestPyPI simple-index propagation, a fresh environment installed `trustweave==0.3.0` from `https://test.pypi.org/simple/`. The console command, module entry point, and import-visible package version each reported `0.3.0`; `trustweave schema list` completed successfully.

## PyPI exact-file verification

The production wheel was published at:

```text
https://files.pythonhosted.org/packages/a9/52/a58e83b739828995fe096289fe2e64a4dccab0b5ad84e377779577777183/trustweave-0.3.0-py3-none-any.whl
```

Its observed SHA-256 is:

```text
20d479d8cee4712047838203150b3b82352c51df3ce863c10326c26272eac28c
```

The following direct consumer-side command returned `OK: trustweave-0.3.0-py3-none-any.whl`:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  https://files.pythonhosted.org/packages/a9/52/a58e83b739828995fe096289fe2e64a4dccab0b5ad84e377779577777183/trustweave-0.3.0-py3-none-any.whl
```

A fresh virtual environment installed `trustweave==0.3.0` from `https://pypi.org/simple/`. The console CLI, `python -m trustweave`, and import-visible package version each reported `0.3.0`; `trustweave schema list` completed successfully.

## Scope of this record

The evidence above establishes observed publication and expected-repository provenance verification for the exact named TestPyPI and PyPI wheel files. It does not establish runtime enforcement, deployed-agent security, authenticity of arbitrary review inputs, live MCP-server behavior, user adoption, productivity, or incident reduction. TrustWeave remains a local, deterministic, non-executing review-evidence tool.

## References

[1]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
[2]: https://docs.pypi.org/api/integrity/ "PyPI: Integrity API"
[3]: https://pypi.org/project/pypi-attestations/ "pypi-attestations"
[4]: https://packaging.python.org/guides/using-testpypi/ "Python Packaging User Guide: Using TestPyPI"
