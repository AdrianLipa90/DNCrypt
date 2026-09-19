from pathlib import Path

import pytest

from dncrypt.project_boundary import (
    RETAINED_PROJECTS,
    assert_package_boundary,
    audit_package_boundary,
)


def test_dncrypt_package_is_independent_of_retained_projects():
    package_root = Path(__file__).parents[1] / "src" / "dncrypt"
    receipt = assert_package_boundary(package_root)
    assert receipt.pass_boundary
    assert receipt.forbidden_imports == ()
    assert "PNCS" in RETAINED_PROJECTS
    assert "GREMLIN" in RETAINED_PROJECTS
    assert "PNV-State-Memory" in RETAINED_PROJECTS
    assert "PNH5" in RETAINED_PROJECTS


def test_boundary_fails_closed_on_retained_project_import(tmp_path):
    package_root = tmp_path / "dncrypt"
    package_root.mkdir()
    (package_root / "bad.py").write_text("import noema.runtime\n", encoding="utf-8")
    receipt = audit_package_boundary(package_root)
    assert not receipt.pass_boundary
    assert receipt.forbidden_imports == ("bad.py:noema",)
    with pytest.raises(RuntimeError, match="project boundary violation"):
        assert_package_boundary(package_root)
