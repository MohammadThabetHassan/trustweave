# TrustWeave 0.2.3 Release Evidence

This record documents the observed publication and package-provenance checks for the exact `v0.2.3` release tag. It is evidence for these specific distribution files only; it does not certify the product, deployed agent systems, or future package versions.

| Item | Observed value |
| --- | --- |
| Release tag | [`v0.2.3`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.2.3) |
| Tagged commit | `4aed7df9d16907804f8c2460c004a4dc685904bc` |
| TestPyPI trusted-publishing workflow | [run 32275683187](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32275683187), completed successfully |
| PyPI trusted-publishing workflow | [run 32276249521](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32276249521), completed successfully |
| GitHub Release | [TrustWeave 0.2.3](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.3) |
| Expected publisher repository | `https://github.com/MohammadThabetHassan/trustweave` |

## TestPyPI exact-file verification

The TestPyPI wheel was published at:

```text
https://test-files.pythonhosted.org/packages/73/d4/a116aa41e6392460b3755b508ade37756e811bd399fe888f3152cad3ef64/trustweave-0.2.3-py3-none-any.whl
```

Its observed SHA-256 is:

```text
01995a19c2646c309479464de704b089d2cf5732d02b7744915f340391d8ac85
```

The TestPyPI Integrity API returned a provenance object at:

```text
https://test.pypi.org/integrity/trustweave/0.2.3/trustweave-0.2.3-py3-none-any.whl/provenance
```

That provenance named publisher repository `MohammadThabetHassan/trustweave` and workflow `publish-testpypi.yml`. After downloading the exact wheel under its original filename and saving that provenance object locally, the following command returned `OK: trustweave-0.2.3-py3-none-any.whl`:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  --provenance-file trustweave-0.2.3-py3-none-any.whl.provenance \
  trustweave-0.2.3-py3-none-any.whl
```

The direct TestPyPI file URL is not accepted by the verifier's `verify pypi` URL mode, which restricts direct URLs to `files.pythonhosted.org`. Supplying the TestPyPI Integrity API provenance object with the exact downloaded file is the observed supported local-file verification path.

A fresh virtual environment installed `trustweave==0.2.3` from `https://test.pypi.org/simple/` after simple-index propagation. The console CLI, `python -m trustweave`, and import-visible package version each reported `0.2.3`; `trustweave schema list` completed successfully.

## PyPI exact-file verification

The production wheel was published at:

```text
https://files.pythonhosted.org/packages/3d/e9/d06671b11bbef312445bd702597752af12b0ce45414bbfa31d642513fef9/trustweave-0.2.3-py3-none-any.whl
```

The following direct consumer-side command returned `OK: trustweave-0.2.3-py3-none-any.whl`:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  https://files.pythonhosted.org/packages/3d/e9/d06671b11bbef312445bd702597752af12b0ce45414bbfa31d642513fef9/trustweave-0.2.3-py3-none-any.whl
```

A fresh virtual environment installed `trustweave==0.2.3` from `https://pypi.org/simple/`. The console CLI, `python -m trustweave`, and import-visible package version each reported `0.2.3`; `trustweave schema list` completed successfully.

## References

[1]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
[2]: https://docs.pypi.org/api/integrity/ "PyPI: Integrity API"
[3]: https://pypi.org/project/pypi-attestations/ "pypi-attestations"
[4]: https://packaging.python.org/guides/using-testpypi/ "Python Packaging User Guide: Using TestPyPI"
