from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DATA = Path(__file__).resolve().parent / "fixtures" / "data"

try:  # works when the package is installed or PYTHONPATH=src
    import deaddrop_hunter.exporters  # noqa: F401
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(ROOT / "src"))

from deaddrop_hunter.exporters import FORMATS, run_exports  # noqa: E402


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return FIXTURE_DATA


@pytest.fixture(scope="session")
def fixture_data(data_dir: Path) -> dict:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in data_dir.glob("*.json")}


@pytest.fixture(scope="session")
def exported(tmp_path_factory, data_dir: Path) -> tuple[Path, list[Path]]:
    out = tmp_path_factory.mktemp("feeds")
    written = run_exports(data_dir, out, list(FORMATS))
    return out, written


@pytest.fixture(scope="session")
def bundle(exported) -> dict:
    out, _ = exported
    return json.loads((out / "stix" / "deaddrop-hunter.bundle.json").read_text(encoding="utf-8"))
