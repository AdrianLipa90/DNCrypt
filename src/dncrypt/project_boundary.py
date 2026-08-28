from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
from pathlib import Path

from .util import blake2b256, canonical_json_bytes

BOUNDARY_SCHEMA = "dncrypt.project-boundary/v0.1"

# These namespaces belong to adjacent projects and must remain external to the
# DNCrypt transferable package. DNCrypt may integrate with them only through
# explicit adapter/port contracts.
RETAINED_PROJECTS: tuple[str, ...] = (
    "PNCS",
    "GREMLIN",
    "NOEMA",
    "CIEL",
    "PhaseNav",
    "PNV-State-Memory",
    "PNFS",
    "PNH5",
)

FORBIDDEN_IMPORT_ROOTS: frozenset[str] = frozenset(
    {
        "pncs",
        "gremlin",
        "noema",
        "ciel",
        "phasenav",
        "pnv_state_memory",
        "pnvstatememory",
        "pnfs",
        "pnh5",
    }
)


@dataclass(frozen=True, slots=True)
class ProjectBoundaryReceipt:
    schema: str
    package_root: str
    scanned_python_files: int
    forbidden_imports: tuple[str, ...]
    retained_projects: tuple[str, ...]
    pass_boundary: bool

    @property
    def digest(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def _root_name(name: str | None) -> str | None:
    if not name:
        return None
    return name.split(".", 1)[0].lower().replace("-", "_")


def _imports_from_file(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = _root_name(alias.name)
                if root:
                    roots.add(root)
        elif isinstance(node, ast.ImportFrom):
            # Relative imports are internal to DNCrypt and therefore allowed.
            if node.level == 0:
                root = _root_name(node.module)
                if root:
                    roots.add(root)
    return tuple(sorted(roots))


def audit_package_boundary(package_root: str | Path) -> ProjectBoundaryReceipt:
    root = Path(package_root).resolve()
    if not root.is_dir():
        raise ValueError("package_root must be a directory")
    py_files = tuple(sorted(root.rglob("*.py")))
    violations: list[str] = []
    for path in py_files:
        for imported_root in _imports_from_file(path):
            if imported_root in FORBIDDEN_IMPORT_ROOTS:
                rel = path.relative_to(root).as_posix()
                violations.append(f"{rel}:{imported_root}")
    return ProjectBoundaryReceipt(
        schema=BOUNDARY_SCHEMA,
        package_root=root.name,
        scanned_python_files=len(py_files),
        forbidden_imports=tuple(sorted(violations)),
        retained_projects=RETAINED_PROJECTS,
        pass_boundary=not violations,
    )


def assert_package_boundary(package_root: str | Path) -> ProjectBoundaryReceipt:
    receipt = audit_package_boundary(package_root)
    if not receipt.pass_boundary:
        joined = ", ".join(receipt.forbidden_imports)
        raise RuntimeError(f"DNCrypt project boundary violation: {joined}")
    return receipt
