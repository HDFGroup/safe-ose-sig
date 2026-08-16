#!/usr/bin/env python3
"""Check the local SSP side of the h5policy evidence contract."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "registry/h5policy-control-evidence.json"
POLICY = ROOT.parent / "policy/README.md"
GUIDE = ROOT / "policy/H5Policy Control Evidence Contract.md"

# The hdf5-pickles producer contract, when that repository is checked out beside
# this one. Located by env override first, then a sibling-directory convention.
PRODUCER_REL = "registry/ssp-control-evidence.yml"
PRODUCER_ENV = "HDF5_PICKLES_DIR"
PRODUCER_SIBLINGS = ("hdf5-pickles",)
# A control id as written in the producer YAML's `- id:` rows. Matched with a
# stdlib regex rather than a YAML parser so this checker keeps its stdlib-only
# dependency footprint; the producer side validates the YAML's structure.
PRODUCER_ID_RE = re.compile(r"^\s*-\s*id:\s*(HDF5-SHINES-[A-Za-z]+-\d+)\s*$", re.MULTILINE)


def normalise(value: str) -> str:
    return value.replace("\u2011", "-").replace("\u2010", "-")


def fail(message: str) -> None:
    print(f"H5POLICY CONTRACT CHECK FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def locate_producer() -> Path | None:
    """The pickles producer contract if the sibling repo is available, else None."""
    bases = []
    env = os.environ.get(PRODUCER_ENV)
    if env:
        bases.append(Path(env))
    bases.extend(ROOT.parent.parent / name for name in PRODUCER_SIBLINGS)
    for base in bases:
        candidate = base / PRODUCER_REL
        if candidate.is_file():
            return candidate
    return None


def check_cross_seam(consumer_ids: set[str]) -> None:
    """The imported control set must equal the producer's control set.

    Each repo's own checker validates its side; only this comparison catches a
    control added to (or dropped from) one contract alone. Skips with a notice
    (never a failure) when the producer repo is absent, so a lone checkout still
    gates.
    """
    producer_path = locate_producer()
    if producer_path is None:
        print(f"H5POLICY CROSS-SEAM CHECK SKIPPED: {PRODUCER_REL} not found "
              f"(set {PRODUCER_ENV} or check out hdf5-pickles beside this repo)")
        return
    text = normalise(producer_path.read_text(encoding="utf-8"))
    producer_ids = {normalise(m) for m in PRODUCER_ID_RE.findall(text)}
    if not producer_ids:
        fail(f"no control ids found in producer contract {producer_path.name}")
    only_consumer = sorted(consumer_ids - producer_ids)
    only_producer = sorted(producer_ids - consumer_ids)
    if only_consumer or only_producer:
        detail = []
        if only_consumer:
            detail.append(f"only in consumer: {', '.join(only_consumer)}")
        if only_producer:
            detail.append(f"only in producer: {', '.join(only_producer)}")
        fail("consumer and h5policy producer control sets disagree (" + "; ".join(detail) + ")")
    print(f"H5POLICY CROSS-SEAM CHECK OK: {len(consumer_ids)} controls match the producer")


def main() -> int:
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read contract: {exc}")
    if contract.get("schema_version") != 1:
        fail("schema_version must be 1")
    producer = contract.get("producer")
    if not isinstance(producer, dict):
        fail("producer must be a mapping")
    for key in ("repository", "contract_path", "validator"):
        if not isinstance(producer.get(key), str) or not producer[key]:
            fail(f"producer.{key} must be a non-empty string")
    consumer = contract.get("consumer")
    required = consumer.get("release_import_requirements") if isinstance(consumer, dict) else None
    if not isinstance(required, list) or len(required) < 4:
        fail("consumer must define the four release import requirements")
    controls = contract.get("controls")
    if not isinstance(controls, list) or len(controls) != len(set(controls)):
        fail("controls must be a non-empty list of unique ids")
    policy_text = normalise(POLICY.read_text(encoding="utf-8"))
    for control in controls:
        if not isinstance(control, str) or normalise(control) not in policy_text:
            fail(f"control is not defined by the policy manual: {control!r}")
    guide = GUIDE.read_text(encoding="utf-8")
    for marker in ("Evidence boundary", "Importing evidence for a release", "hdf5-pickles"):
        if marker not in guide:
            fail(f"guide lacks {marker!r}")
    check_cross_seam({normalise(c) for c in controls})
    print(f"H5POLICY CONTRACT CHECK OK: {len(controls)} SSP controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
