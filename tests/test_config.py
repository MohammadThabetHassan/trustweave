from __future__ import annotations

from pathlib import Path

import pytest

from trustweave.cli import main
from trustweave.config import CONFIG_FILE_NAME, init_project, load_project_config
from trustweave.models import InputOutputError, ValidationError


def test_init_creates_a_local_template_and_never_overwrites(tmp_path: Path) -> None:
    assert main(["init", "--directory", str(tmp_path)]) == 0
    config_path = tmp_path / CONFIG_FILE_NAME
    assert config_path.is_file()
    assert load_project_config(config_path)["output_dir"] == "artifacts"
    with pytest.raises(InputOutputError, match="Refusing"):
        init_project(tmp_path)


def test_project_config_rejects_unknown_and_non_string_values(tmp_path: Path) -> None:
    path = tmp_path / CONFIG_FILE_NAME
    path.write_text("[tool.trustweave]\nunknown = 'value'\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="unknown field"):
        load_project_config(path)
    path.write_text("[tool.trustweave]\nmanifest = 1\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="non-empty string"):
        load_project_config(path)
