from pathlib import Path

import pandas as pd
import pytest

from src.parser.csv_parser import CsvValidationError, load_network_csv


FIXTURE = Path("tests/fixtures/sample_raw_network_log.csv")


def test_load_network_csv_normalizes_and_loads_raw_fixture():
    df = load_network_csv(FIXTURE)

    assert len(df) == 8
    assert {"srcip", "dstip", "dsport"}.issubset(df.columns)
    assert str(df["dsport"].dtype) == "Int64"


def test_load_network_csv_rejects_missing_required_shape(tmp_path):
    bad_csv = tmp_path / "bad.csv"
    pd.DataFrame({"source": ["10.0.0.1"], "target": ["10.0.0.2"]}).to_csv(
        bad_csv, index=False
    )

    with pytest.raises(CsvValidationError):
        load_network_csv(bad_csv)
