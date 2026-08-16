import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = "audit/scripts/import_h5policy_evidence.py"


def _fake_producer(tmp_path, libhdf5_version):
    """A minimal producer repo carrying a contract that checks out trivially."""
    repo = tmp_path / "hdf5-pickles"
    (repo / "registry").mkdir(parents=True)
    (repo / "tools").mkdir(parents=True)
    (repo / "registry/ssp-control-evidence.yml").write_text(
        "schema_version: 1\n"
        "producer: h5policy\n"
        f"measurement:\n  libhdf5_version: {libhdf5_version}\n"
        "controls:\n"
        "  - id: HDF5-SHINES-TEST-05\n    record: dense_index\n    fixture: f.yml\n",
        encoding="utf-8",
    )
    # A stand-in checker that always passes, so the importer's own logic is under
    # test rather than the real producer registry.
    (repo / "tools/check_ssp_control_evidence.py").write_text(
        "print('SSP EVIDENCE CHECK OK: stub')\n", encoding="utf-8")
    return repo


def _run(component, version, producer):
    import os
    env = dict(os.environ)
    env["HDF5_PICKLES_DIR"] = str(producer)
    return subprocess.run(
        [sys.executable, SCRIPT, component, version],
        cwd=ROOT, text=True, capture_output=True, check=False, env=env,
    )


def test_import_writes_provenance_when_versions_align(tmp_path):
    producer = _fake_producer(tmp_path, "9.9.9")
    dest = ROOT / "audit/proofs/hdf5-core/9.9.9"
    (dest).mkdir(parents=True, exist_ok=True)
    try:
        result = _run("hdf5-core", "9.9.9", producer)
        assert result.returncode == 0, result.stderr
        prov = json.loads((dest / "control-evidence/provenance.json").read_text())
        assert prov["libhdf5_version"] == "9.9.9"
        assert prov["controls"] == ["HDF5-SHINES-TEST-05"]
        assert prov["contract_sha256"]
    finally:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)


def test_import_fails_on_version_misalignment(tmp_path):
    producer = _fake_producer(tmp_path, "2.2.0")
    dest = ROOT / "audit/proofs/hdf5-core/1.0.0"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        result = _run("hdf5-core", "1.0.0", producer)
        assert result.returncode == 1
        assert "version misalignment" in result.stderr
    finally:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
