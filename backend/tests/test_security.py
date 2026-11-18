import io, zipfile
from pathlib import Path
import pytest
from app.security import safe_extract_zip

def make_zip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, content in entries:
            z.writestr(name, content)
    return b.getvalue()

def test_safe_zip_extracts(tmp_path):
    data = make_zip([("app.py", "print('hello')")])
    assert safe_extract_zip(data, tmp_path / "out") == 1
    assert (tmp_path / "out" / "app.py").exists()

def test_rejects_path_traversal(tmp_path):
    data = make_zip([("../escape.txt", "bad")])
    with pytest.raises(ValueError):
        safe_extract_zip(data, tmp_path / "out")
