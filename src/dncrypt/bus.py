from __future__ import annotations
from dataclasses import dataclass, asdict
import json, os, tempfile
from pathlib import Path
from .fitness import FitnessRecord, PopulationFitnessReport
from .genome import CipherGenome, population_commitment
from .util import canonical_json_bytes, blake2b256

REQUIRED_METRICS = (
    "structural_leakage", "predictability", "delta_bits", "delta_alpha",
    "avalanche_bias", "throughput", "decrypt_failures", "integrity_failures", "p_value",
)

@dataclass(frozen=True, slots=True)
class EvaluationRequest:
    schema: str
    parent_genome_id: str
    generation: int
    population_commitment: str
    candidate_genome_ids: tuple[str, ...]
    required_metrics: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema != "dncrypt.evaluation-request/v0.2":
            raise ValueError("unsupported request schema")
        if self.generation < 0 or len(self.candidate_genome_ids) == 0:
            raise ValueError("invalid generation/population")
        if len(set(self.candidate_genome_ids)) != len(self.candidate_genome_ids):
            raise ValueError("candidate ids must be unique")
        if self.required_metrics != REQUIRED_METRICS:
            raise ValueError("required metric contract mismatch")

    @property
    def request_id(self) -> str:
        return blake2b256(canonical_json_bytes(asdict(self)))


def make_evaluation_request(parent: CipherGenome, population: tuple[CipherGenome, ...]) -> EvaluationRequest:
    if not population:
        raise ValueError("population must not be empty")
    if any(g.parent_id != parent.genome_id or g.generation != parent.generation + 1 for g in population):
        raise ValueError("population lineage mismatch")
    return EvaluationRequest(
        "dncrypt.evaluation-request/v0.2", parent.genome_id, parent.generation + 1,
        population_commitment(population), tuple(g.genome_id for g in population), REQUIRED_METRICS,
    )


def write_evaluation_request(path: str | Path, request: EvaluationRequest) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    value = asdict(request); value["request_id"] = request.request_id
    data = canonical_json_bytes(value) + b"\n"
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", dir=str(p.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def load_external_evaluation(path: str | Path, request: EvaluationRequest, population: tuple[CipherGenome, ...]) -> PopulationFitnessReport:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema") != "dncrypt.external-evaluation/v0.2":
        raise ValueError("unsupported external evaluation schema")
    if value.get("request_id") != request.request_id:
        raise ValueError("external evaluation request_id mismatch")
    raw_records = value.get("records")
    if not isinstance(raw_records, list):
        raise ValueError("external evaluation records must be a list")
    report = PopulationFitnessReport(value["schema"], value["request_id"], tuple(FitnessRecord(**item) for item in raw_records))
    report.validate_population(population)
    return report
