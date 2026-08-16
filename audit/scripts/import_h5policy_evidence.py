#!/usr/bin/env python3
"""Import H5Policy control-evidence into a release proof bundle.

Realises the ritual in
`audit/policy/H5Policy Control Evidence Contract.md`: it copies the producer's
checked contract into `proofs/<component>/<version>/control-evidence/`, records the
producer commit and the SHA-256 of the copied contract, captures the producer
checker's output from that same revision, and records the measured
`libhdf5_version`.

Crucially, it asserts that the contract's measured `libhdf5_version` equals the
release <version> being imported into, so evidence measured against one release
cannot be filed under another -- the coupling the contract prose leaves implicit.

Usage:
  python3 audit/scripts/import_h5policy_evidence.py hdf5-core 2.2.0
  HDF5_PICKLES_DIR=/path/to/hdf5-pickles python3 ... hdf5-core 2.2.0

The producer repository is located by $HDF5_PICKLES_DIR, then by the
`hdf5-pickles` sibling-directory convention. Nothing is fetched over the network.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("import_h5policy_evidence: PyYAML is required (pip install pyyaml)")

ROOT = Path(__file__).resolve().parents[1]          # the audit/ root
COMPONENTS = {"hdf5-core", "hdfview"}
PRODUCER_ENV = "HDF5_PICKLES_DIR"
PRODUCER_SIBLINGS = ("hdf5-pickles",)
CONTRACT_REL = "registry/ssp-control-evidence.yml"
CHECKER_REL = "tools/check_ssp_control_evidence.py"


def fail(message: str) -> None:
    print(f"IMPORT FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def locate_producer() -> Path:
    bases = []
    env = os.environ.get(PRODUCER_ENV)
    if env:
        bases.append(Path(env))
    # audit/ -> repo root -> its parent holds sibling repos
    bases.extend(ROOT.parent.parent / name for name in PRODUCER_SIBLINGS)
    for base in bases:
        if (base / CONTRACT_REL).is_file():
            return base
    fail(f"producer contract {CONTRACT_REL} not found "
         f"(set {PRODUCER_ENV} or check out hdf5-pickles beside this repo)")


def git_commit(repo: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable ({exc})"
    return out.stdout.strip() if out.returncode == 0 else "unavailable (not a git repo)"


def git_dirty(repo: Path) -> bool:
    try:
        out = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(out.stdout.strip())


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in COMPONENTS:
        print(__doc__.strip())
        return 2
    component, version = sys.argv[1], sys.argv[2]

    dest = ROOT / "proofs" / component / version / "control-evidence"
    if not dest.parent.parent.is_dir():
        fail(f"release bundle {dest.parent} does not exist "
             f"(create it first, e.g. `python3 audit/scripts/new_release.py {component} {version}`)")
    dest.mkdir(parents=True, exist_ok=True)

    producer = locate_producer()
    contract_path = producer / CONTRACT_REL
    contract_bytes = contract_path.read_bytes()
    contract = yaml.safe_load(contract_bytes.decode("utf-8"))

    measured = (contract.get("measurement") or {}).get("libhdf5_version")
    if measured is None:
        fail("producer contract has no measurement.libhdf5_version")
    if str(measured) != str(version):
        fail(f"version misalignment: contract measures libhdf5 {measured!r} but this "
             f"import targets release {version!r}. Import into proofs/{component}/{measured}/ "
             f"instead, or re-measure the contract against {version}.")

    # Capture the producer checker's own verdict, from the producer revision.
    checker = producer / CHECKER_REL
    proc = subprocess.run([sys.executable, str(checker)], cwd=str(producer),
                          capture_output=True, text=True)
    checker_output = proc.stdout + proc.stderr
    if proc.returncode != 0:
        (dest / "checker-output.txt").write_text(checker_output, encoding="utf-8")
        fail(f"producer checker failed (exit {proc.returncode}); output written to "
             f"{dest / 'checker-output.txt'}. Do not import evidence that does not check out.")

    sha256 = hashlib.sha256(contract_bytes).hexdigest()
    control_ids = sorted({row.get("id") for row in contract.get("controls", [])
                          if isinstance(row, dict)})
    provenance = {
        "imported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer_repository": "HDFGroup/hdf5-pickles",
        "producer_commit": git_commit(producer),
        "producer_worktree_dirty": git_dirty(producer),
        "contract_path": CONTRACT_REL,
        "contract_sha256": sha256,
        "libhdf5_version": str(measured),
        "release_component": component,
        "release_version": version,
        "controls": control_ids,
        "row_count": len(contract.get("controls", [])),
        "checker": CHECKER_REL,
        "checker_exit": proc.returncode,
    }

    (dest / "imported-contract.yml").write_bytes(contract_bytes)
    (dest / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n",
                                          encoding="utf-8")
    (dest / "checker-output.txt").write_text(checker_output, encoding="utf-8")

    if provenance["producer_worktree_dirty"]:
        print("WARNING: producer worktree is dirty; the pinned commit does not fully "
              "describe the imported contract. Commit the producer before a release import.")
    print(f"IMPORT OK: {component} {version} <- libhdf5 {measured}, "
          f"{len(control_ids)} controls / {provenance['row_count']} rows, "
          f"contract sha256 {sha256[:16]}...")
    print(f"  wrote {dest.relative_to(ROOT)}/{{imported-contract.yml,provenance.json,checker-output.txt}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
