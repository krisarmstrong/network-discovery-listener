import pytest
from extension_file_organizer import get_year_month_prefix

def test_get_year_month_prefix(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("data")
    prefix = get_year_month_prefix(str(f))
    assert len(prefix) == 7  # format YYYY-MM
