# Release evidence: TrustWeave 0.2.3

This page records the observed publication and package-provenance checks for the exact `v0.2.3` release. It is evidence for the named distribution files only. It is **not** a security certification, a claim about future releases, or evidence about deployed agent systems.

| Item | Observed value |
| --- | --- |
| Release tag | [`v0.2.3`](https://github.com/MohammadThabetHassan/trustweave/tree/v0.2.3) |
| Tagged commit | `4aed7df9d16907804f8c2460c004a4dc685904bc` |
| TestPyPI workflow | [run 32275683187](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32275683187), passed |
| PyPI workflow | [run 32276249521](https://github.com/MohammadThabetHassan/trustweave/actions/runs/32276249521), passed |
| GitHub Release | [TrustWeave 0.2.3](https://github.com/MohammadThabetHassan/trustweave/releases/tag/v0.2.3) |
| Expected publisher repository | `https://github.com/MohammadThabetHassan/trustweave` |

## TestPyPI record

The exact TestPyPI wheel is available at:

```text
https://test-files.pythonhosted.org/packages/73/d4/a116aa41e6392460b3755b508ade37756e811bd399fe888f3152cad3ef64/trustweave-0.2.3-py3-none-any.whl
```

Its SHA-256 is `01995a19c2646c309479464de704b089d2cf5732d02b7744915f340391d8ac85`. The matching provenance object was obtained from the [TestPyPI Integrity API](https://test.pypi.org/integrity/trustweave/0.2.3/trustweave-0.2.3-py3-none-any.whl/provenance). It named publisher repository `MohammadThabetHassan/trustweave` and workflow `publish-testpypi.yml`.

The direct-URL verifier mode accepts production `files.pythonhosted.org` URLs, not TestPyPI’s `test-files.pythonhosted.org` host. The TestPyPI wheel was therefore downloaded without modification under its original filename, then verified with the matching provenance object:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  --provenance-file trustweave-0.2.3-py3-none-any.whl.provenance \
  trustweave-0.2.3-py3-none-any.whl
```

The command returned `OK: trustweave-0.2.3-py3-none-any.whl`. A fresh environment also installed `trustweave==0.2.3` from TestPyPI; the console command, module entry point, and import-visible version each reported `0.2.3`, and `trustweave schema list` completed successfully.

## PyPI record

The exact production wheel is available at:

```text
https://files.pythonhosted.org/packages/3d/e9/d06671b11bbef312445bd702597752af12b0ce45414bbfa31d642513fef9/trustweave-0.2.3-py3-none-any.whl
```

The direct consumer verification command returned `OK: trustweave-0.2.3-py3-none-any.whl`:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/MohammadThabetHassan/trustweave \
  https://files.pythonhosted.org/packages/3d/e9/d06671b11bbef312445bd702597752af12b0ce45414bbfa31d642513fef9/trustweave-0.2.3-py3-none-any.whl
```

A fresh environment also installed `trustweave==0.2.3` from PyPI; the console command, module entry point, and import-visible version each reported `0.2.3`, and `trustweave schema list` completed successfully.

For the repository-maintained source record, see [Release Evidence 0.2.3](https://github.com/MohammadThabetHassan/trustweave/blob/main/docs/RELEASE_EVIDENCE_0.2.3.md).

## References

[1]: https://docs.pypi.org/attestations/consuming-attestations/ "PyPI: Consuming attestations"
[2]: https://docs.pypi.org/api/integrity/ "PyPI: Integrity API"
[3]: https://pypi.org/project/pypi-attestations/ "pypi-attestations"
