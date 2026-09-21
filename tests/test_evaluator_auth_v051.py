from __future__ import annotations

from dataclasses import asdict
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dncrypt import FitnessRecord, PopulationFitnessReport, initial_genome, make_evaluation_request, vectorized_mutation_population
from dncrypt.evaluator_auth import (
    SignedEvaluationEnvelope,
    load_signed_external_evaluation,
    sign_evaluation_report,
    verify_signed_evaluation,
)


def _fixture():
    parent = initial_genome(bytes(range(64)))
    population = vectorized_mutation_population(parent, 2, b"e" * 128)
    request = make_evaluation_request(parent, population)
    records = tuple(
        FitnessRecord(
            genome_id=g.genome_id,
            generation=g.generation,
            structural_leakage=0.01,
            predictability=0.01,
            delta_bits=0.0,
            delta_alpha=0.0,
            avalanche_bias=0.01,
            throughput=100.0,
            decrypt_failures=0,
            integrity_failures=0,
            p_value=0.9,
            source="signed-evaluator-test",
        )
        for g in population
    )
    report = PopulationFitnessReport("dncrypt.external-evaluation/v0.2", request.request_id, records)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return parent, population, request, report, private, public


def test_signed_external_evaluation_verifies_for_trusted_evaluator():
    _, population, request, report, private, public = _fixture()
    signed = sign_evaluation_report(report, "lab-a", private)
    verified = verify_signed_evaluation(signed, {"lab-a": public})
    assert verified == report
    verified.validate_population(population)
    assert verified.request_id == request.request_id


def test_unknown_evaluator_fails_closed():
    _, _, _, report, private, _ = _fixture()
    signed = sign_evaluation_report(report, "lab-a", private)
    with pytest.raises(ValueError, match="untrusted"):
        verify_signed_evaluation(signed, {})


def test_metric_tamper_after_signature_fails_closed():
    _, _, _, report, private, public = _fixture()
    signed = sign_evaluation_report(report, "lab-a", private)
    value = signed.to_dict()
    value["report"]["records"][0]["structural_leakage"] = 0.0
    tampered = SignedEvaluationEnvelope.from_dict(value)
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signed_evaluation(tampered, {"lab-a": public})


def test_signed_file_loader_binds_request_and_population(tmp_path):
    _, population, request, report, private, public = _fixture()
    signed = sign_evaluation_report(report, "lab-a", private)
    p = tmp_path / "signed-report.json"
    p.write_text(json.dumps(signed.to_dict(), sort_keys=True), encoding="utf-8")
    loaded = load_signed_external_evaluation(p, request, population, {"lab-a": public})
    assert loaded == report


def test_signed_loader_rejects_wrong_request(tmp_path):
    parent, population, _, report, private, public = _fixture()
    signed = sign_evaluation_report(report, "lab-a", private)
    p = tmp_path / "signed-report.json"
    p.write_text(json.dumps(signed.to_dict(), sort_keys=True), encoding="utf-8")
    other_population = vectorized_mutation_population(parent, 2, b"x" * 128)
    other_request = make_evaluation_request(parent, other_population)
    with pytest.raises(ValueError, match="request_id mismatch"):
        load_signed_external_evaluation(p, other_request, population, {"lab-a": public})
