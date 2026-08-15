import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(env_extra=None):
    import os
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "audit/scripts/check_h5policy_contract.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def test_h5policy_contract_is_well_formed_and_policy_backed():
    result = _run()
    assert result.returncode == 0, result.stderr


def _fake_producer(tmp_path, ids):
    """A minimal producer contract carrying just the given control-id rows."""
    contract = tmp_path / "registry/ssp-control-evidence.yml"
    contract.parent.mkdir(parents=True, exist_ok=True)
    rows = "".join(f"  - id: {cid}\n    record: r\n" for cid in ids)
    contract.write_text("schema_version: 1\ncontrols:\n" + rows, encoding="utf-8")
    return tmp_path


def _consumer_ids():
    data = json.loads((ROOT / "audit/registry/h5policy-control-evidence.json").read_text())
    return list(data["controls"])


def test_cross_seam_passes_when_producer_matches(tmp_path):
    producer = _fake_producer(tmp_path, _consumer_ids())
    result = _run({"HDF5_PICKLES_DIR": str(producer)})
    assert result.returncode == 0, result.stderr
    assert "CROSS-SEAM CHECK OK" in result.stdout


def test_cross_seam_fails_when_producer_has_an_extra_control(tmp_path):
    producer = _fake_producer(tmp_path, _consumer_ids() + ["HDF5-SHINES-GOV-99"])
    result = _run({"HDF5_PICKLES_DIR": str(producer)})
    assert result.returncode == 1
    assert "only in producer: HDF5-SHINES-GOV-99" in result.stderr


def _load_checker():
    import importlib.util
    path = ROOT / "audit/scripts/check_h5policy_contract.py"
    spec = importlib.util.spec_from_file_location("check_h5policy_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cross_seam_skips_when_producer_absent(monkeypatch, capsys, tmp_path):
    # Isolate the locator so the real sibling repo cannot be found: no env
    # override and a sibling name that does not exist. The check must skip with a
    # notice and never fail, so a lone SSP checkout still gates.
    checker = _load_checker()
    monkeypatch.delenv("HDF5_PICKLES_DIR", raising=False)
    monkeypatch.setattr(checker, "PRODUCER_SIBLINGS", ("no-such-sibling-xyz",))
    assert checker.locate_producer() is None
    checker.check_cross_seam({"HDF5-SHINES-TEST-05"})  # must not raise SystemExit
    assert "CROSS-SEAM CHECK SKIPPED" in capsys.readouterr().out
