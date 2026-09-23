from __future__ import annotations

import pytest

from dncrypt.pdna import PDNA_MAX_BYTES, PDNARecord


def test_pdna_rejects_oversized_payload_before_json_or_recursive_parse():
    with pytest.raises(ValueError, match="maximum size"):
        PDNARecord.from_bytes(b"{" + b"x" * PDNA_MAX_BYTES)
