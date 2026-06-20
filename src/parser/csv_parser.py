from __future__ import annotations

from pathlib import Path

import pandas as pd


RAW_REQUIRED_COLUMNS = {"srcip", "dstip", "dsport"}
UNSW_REQUIRED_COLUMNS = {"ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm"}
OPTIONAL_NUMERIC_COLUMNS = {
    "dsport",
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_src_ltm",
    "ct_srv_dst",
    "label",
}


class CsvValidationError(ValueError):
    """Raised when an input CSV cannot be used by the detection pipeline."""


def load_network_csv(path: str | Path) -> pd.DataFrame:
    csv_path = Path(path)
    if not csv_path.exists():
        raise CsvValidationError(f"file does not exist: {csv_path}")

    try:
        df = pd.read_csv(csv_path)
    except Exception as exc:
        raise CsvValidationError(f"could not read CSV: {exc}") from exc

    if df.empty:
        raise CsvValidationError("CSV is empty")

    df.columns = [str(column).strip().lower() for column in df.columns]
    columns = set(df.columns)
    has_raw_shape = RAW_REQUIRED_COLUMNS.issubset(columns)
    has_unsw_shape = UNSW_REQUIRED_COLUMNS.issubset(columns)

    if not has_raw_shape and not has_unsw_shape:
        missing_raw = ", ".join(sorted(RAW_REQUIRED_COLUMNS - columns))
        missing_unsw = ", ".join(sorted(UNSW_REQUIRED_COLUMNS - columns))
        raise CsvValidationError(
            "CSV must contain either raw log columns "
            f"({', '.join(sorted(RAW_REQUIRED_COLUMNS))}) or cleaned UNSW behavior columns. "
            f"Missing raw columns: {missing_raw or 'none'}; "
            f"missing UNSW columns: {missing_unsw or 'none'}."
        )

    if has_raw_shape:
        df = df.dropna(subset=["srcip", "dstip"]).copy()
        df["srcip"] = df["srcip"].astype(str).str.strip()
        df["dstip"] = df["dstip"].astype(str).str.strip()

    for column in OPTIONAL_NUMERIC_COLUMNS.intersection(df.columns):
        df[column] = pd.to_numeric(df[column], errors="coerce")

    if "dsport" in df.columns:
        df = df.dropna(subset=["dsport"]).copy()
        df["dsport"] = df["dsport"].astype("Int64")

    if df.empty:
        raise CsvValidationError("CSV has no usable rows after cleaning")

    return df
