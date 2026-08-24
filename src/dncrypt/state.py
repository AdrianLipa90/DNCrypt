from __future__ import annotations
from dataclasses import dataclass, asdict
import json, os, tempfile
from pathlib import Path
from .genome import CipherGenome
from .surface import CipherSurface

@dataclass(frozen=True, slots=True)
class DNCryptState:
    genome: CipherGenome
    surface: CipherSurface
    last_receipt: str | None = None
    last_evolution_receipt: str | None = None

    def __post_init__(self) -> None:
        if self.surface.tick < 0:
            raise ValueError("invalid tick")


def save_state_atomic(path: str | Path, state: DNCryptState) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    value = {"schema": "dncrypt.state/v0.2", "genome": asdict(state.genome), "surface": asdict(state.surface), "last_receipt": state.last_receipt, "last_evolution_receipt": state.last_evolution_receipt}
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", dir=str(p.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def load_state(path: str | Path) -> DNCryptState:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema") != "dncrypt.state/v0.2":
        raise ValueError("unsupported state schema")
    g = dict(value["genome"]); g["operator_vector"] = tuple(g["operator_vector"]); g["route"] = tuple(g["route"])
    surf = dict(value["surface"]); surf["phi"] = tuple(surf["phi"]); surf["omega"] = tuple(surf["omega"])
    return DNCryptState(CipherGenome(**g), CipherSurface(**surf), value.get("last_receipt"), value.get("last_evolution_receipt"))
