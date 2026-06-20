from __future__ import annotations

from pathlib import Path

import pandas as pd


REPORT_COLUMNS = [
    "srcip",
    "record_id",
    "classification",
    "severity",
    "risk_score",
    "hybrid_decision",
    "ml_prediction",
    "ml_prediction_label",
    "ml_attack_probability",
    "ml_model_used",
    "connection_count",
    "unique_dstip_count",
    "unique_dsport_count",
    "dst_src_relationship_count",
    "state_ttl_count",
    "attack_cat",
    "label",
    "reason",
]


def write_report(results: pd.DataFrame, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [column for column in REPORT_COLUMNS if column in results.columns]
    results.loc[:, columns].to_csv(path, index=False)
    return path


def print_console_summary(results: pd.DataFrame, output_path: str | Path) -> None:
    print(f"Report written to: {output_path}")
    print(f"Rows in report: {len(results)}")

    if results.empty:
        print("No suspicious activity matched the selected thresholds.")
        return

    print("\nTop suspicious activity:")
    top_rows = results.head(10)
    for row in top_rows.to_dict("records"):
        identity = row.get("srcip", row.get("record_id", "unknown"))
        ml_summary = ""
        if "ml_attack_probability" in row:
            ml_summary = (
                f"; ML={row.get('ml_prediction_label', 'Unknown')} "
                f"({float(row['ml_attack_probability']):.2%})"
            )
        print(
            f"- {identity}: {row['classification']} "
            f"({row['severity']}, score {row['risk_score']}){ml_summary} - {row['reason']}"
        )
