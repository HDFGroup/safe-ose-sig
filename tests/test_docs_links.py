import re
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/h5policy-integration.md"


def test_integration_doc_relative_links_resolve():
    """Every relative (./ or ../) link in the integration doc must exist.

    The doc points at concrete contract, checker, bundle, and policy paths; a
    rename elsewhere in the repo should break this test, not silently rot the doc.
    """
    text = DOC.read_text(encoding="utf-8")
    targets = re.findall(r"\]\((\.\.?/[^)]+)\)", text)
    assert targets, "expected relative links in the integration doc"
    missing = []
    for target in targets:
        path = (DOC.parent / urllib.parse.unquote(target)).resolve()
        if not path.exists():
            missing.append(target)
    assert not missing, f"broken relative links: {missing}"
