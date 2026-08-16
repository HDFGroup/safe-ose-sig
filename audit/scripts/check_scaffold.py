#!/usr/bin/env python3
"""Sanity checks for the scaffold."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ["hdf5-core", "hdfview"]
MUST_HAVE = ["release-bundle", "sbom", "sca", "change-control", "psirt",
             "control-evidence"]

def require(path: Path, label: str) -> bool:
    if not path.exists():
        print(f"ERROR: missing {label}: {path}")
        return False
    return True

def main() -> int:
    ok = True
    ok &= require(ROOT / "policy", "policy folder")
    ok &= require(ROOT / "process", "process folder")
    ok &= require(ROOT / "registry", "registry folder")
    ok &= require(ROOT / "proofs", "proofs folder")
    ok &= require(ROOT / "scripts", "scripts folder")

    for c in COMPONENTS:
        t = ROOT / "proofs" / c / "TEMPLATE"
        ok &= require(t, f"{c} TEMPLATE")
        ok &= require(ROOT / "proofs" / c / "index.md", f"{c} index.md")
        ok &= require(t / "index.md", f"{c} TEMPLATE index.md")
        for d in MUST_HAVE:
            ok &= require(t / d, f"{c} TEMPLATE {d} folder")
            ok &= require(t / d / "README.md", f"{c} TEMPLATE {d}/README.md")
            ok &= require(t / d / "PLACEHOLDER.md", f"{c} TEMPLATE {d}/PLACEHOLDER.md")

    print("OK: scaffold structure looks good." if ok else "FAILED: scaffold has missing items.")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
