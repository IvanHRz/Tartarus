"""Phase 0 — Constraint and smoke tests."""
import subprocess
import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).parent.parent


def test_main_under_500_lines():
    """C2: main.py must stay under 500 lines."""
    main_py = ENGINE_DIR / "main.py"
    lines = len(main_py.read_text().splitlines())
    assert lines < 500, f"main.py has {lines} lines (limit: 500)"


def test_no_pandas_in_engine():
    """C1: No pandas anywhere in engine/."""
    banned = ["im" + "port pan" + "das", "from pan" + "das"]
    for py_file in ENGINE_DIR.rglob("*.py"):
        if "test_" in py_file.name:
            continue
        content = py_file.read_text()
        for pattern in banned:
            assert pattern not in content, f"pandas found in {py_file}"


def test_main_imports():
    """Verify main.py can be parsed without syntax errors."""
    result = subprocess.run(
        [sys.executable, "-c", "import ast; ast.parse(open('main.py').read())"],
        capture_output=True,
        text=True,
        cwd=str(ENGINE_DIR),
    )
    assert result.returncode == 0, f"Syntax error in main.py: {result.stderr}"
